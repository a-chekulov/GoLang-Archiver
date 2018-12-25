package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fullsailor/pkcs7"
	yaml "gopkg.in/yaml.v2"
)

func main() {

	var mode string
	flag.StringVar(&mode, "mode", "i", "")
	var hash string
	flag.StringVar(&hash, "hash", "", "")
	var cert string
	flag.StringVar(&cert, "cert", "./my.crt", "")
	var pkey string
	flag.StringVar(&pkey, "pkey", "./my.key", "")
	var path string
	flag.StringVar(&path, "path", "", "")
	flag.Parse()

	switch mode {
	case "z":
		{
			makeSzip(cert, pkey)
			break
		}
	case "x":
		{
			err := Extract("./extract/", hash, cert, pkey)
			if err != nil {
				log.Printf(err.Error())
				return
			}
			break
		}
	case "i":
		{
			sign, err := Verify()
			if err != nil {
				log.Printf(err.Error())
				return
			}
			if hash != "" {
				signer := sign.GetOnlySigner()
				if hash == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {
					fmt.Println("Хеши одинаковы")
				} else {
					fmt.Println("Хеши не совпадают")
				}
			}
			data := sign.Content
			buf, err := ReadMeta(data)
			if err != nil {
				log.Printf(err.Error())
				return
			}
			fmt.Printf(string(buf.Bytes()))
			break
		}
	default:
		{
			fmt.Print("Неизвестная команда\n")
			break
		}
	}

}

type fileCollector struct {
	ZipBuf   *bytes.Buffer
	Zip      *zip.Writer
	MetaData []*FileMeta
}

func NewFileCollector() *fileCollector {
	buf := new(bytes.Buffer)
	return &fileCollector{
		ZipBuf:   buf,
		Zip:      zip.NewWriter(buf),
		MetaData: make([]*FileMeta, 0, 100),
	}
}

func (f *fileCollector) zipFiles(filename string, fileReader io.Reader) (err error) {
	var fileWriter io.Writer
	if fileWriter, err = f.Zip.Create(filename); err != nil {
		return
	}
	if _, err = io.Copy(fileWriter, fileReader); err != nil {
		return
	}
	return
}

func (f *fileCollector) zipData() (Data []byte, err error) {
	if err = f.Zip.Close(); err != nil {
		return
	}
	Data = f.ZipBuf.Bytes()
	return
}

func wolkFiles(collector *fileCollector, path string) (err error) {
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(path); err != nil {
		return
	}
	for i := range files {
		full := filepath.Join(path, files[i].Name())
		fmt.Println(full)
		if files[i].IsDir() {
			if err = wolkFiles(collector, full); err != nil {
				return
			}
		}
		var dataForHash []byte
		if dataForHash, err = ioutil.ReadFile(full); err != nil {
			return
		}
		s := sha1.Sum(dataForHash)
		collector.addMeta(full, files[i].Size(), files[i].ModTime().Format("2006-01-02 15:04:05"), base64.URLEncoding.EncodeToString(s[:]))
		var fileReader *os.File
		if fileReader, err = os.Open(full); err != nil {
			return
		}
		if err = collector.zipFiles(full, fileReader); err != nil {
			return
		}
	}
	return
}

type FileMeta struct {
	Name         string `yaml:"filename"`
	OriginalSize int64  `yaml:"original_size"`
	ModTime      string `yaml:"mod_time"`
	Hash         string `yaml:"hash"`
}

func (f *fileCollector) meta2YAML() (YAML []byte, err error) {

	return yaml.Marshal(f.MetaData)

}

func (f *fileCollector) addMeta(fullPath string, originalSize int64, modTime string, hash string) {
	f.MetaData = append(f.MetaData, &FileMeta{
		Name:         fullPath,
		OriginalSize: originalSize,
		ModTime:      modTime,
		Hash:         hash,
	})
	return
}

func makeSzip(sert string, pkey string) (err error) {
	collector := NewFileCollector()
	if err = wolkFiles(collector, "./test"); err != nil {
		return
	}
	var YAML []byte
	if YAML, err = collector.meta2YAML(); err != nil {
		return
	}
	fmt.Printf("metaLen = %d\n", len(YAML))
	metaCollector := NewFileCollector()
	if err = metaCollector.zipFiles("meta.yaml", bytes.NewReader(YAML)); err != nil {
		return
	}
	var metaZip []byte
	if metaZip, err = metaCollector.zipData(); err != nil {
		return
	}
	metaLen := len(metaZip)
	fmt.Printf("metaLen = %d\n", metaLen)
	var zipData []byte
	if zipData, err = collector.zipData(); err != nil {
		return
	}
	resultBuf := new(bytes.Buffer)
	if err = binary.Write(resultBuf, binary.LittleEndian, uint32(metaLen)); err != nil {
		return
	}
	if _, err = resultBuf.Write(metaZip); err != nil {
		return
	}
	if _, err = resultBuf.Write(zipData); err != nil {
		return
	}
	var signedData []byte
	if signedData, err = signData(resultBuf.Bytes(), sert, pkey); err != nil {
		return
	}
	if err = ioutil.WriteFile("test.szp", signedData, 0644); err != nil {
		return
	}
	return
}

func signData(data []byte, certif string, pkey string) (signed []byte, err error) {
	var signedData *pkcs7.SignedData
	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}
	var cert tls.Certificate
	if cert, err = tls.LoadX509KeyPair(certif, pkey); err != nil {
		return
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("Не удалось загрузить сертификат")
	}
	rsaKey := cert.PrivateKey
	var rsaCert *x509.Certificate
	if rsaCert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return
	}
	if err = signedData.AddSigner(rsaCert, rsaKey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}
	return signedData.Finish()
}

func Verify() (sign *pkcs7.PKCS7, err error) {
	szip, err := ioutil.ReadFile("test.szp")
	if err != nil {
		log.Printf("Unable to read zip")
		return nil, err
	}
	sign, err = pkcs7.Parse(szip)
	if err != nil {
		log.Printf("Sign is broken!")
		return sign, err
	}
	err = sign.Verify()
	if err != nil {
		log.Printf("Sign is not verified")
		return sign, err
	}
	return sign, nil
}

func ReadMeta(data []byte) (*bytes.Buffer, error) {
	mlen := binary.LittleEndian.Uint32(data[:4]) //получаю длину метаданных
	bmeta := data[4 : mlen+4]                    //получаю байты метаданных
	m, err := zip.NewReader(bytes.NewReader(bmeta), int64(len(bmeta)))
	if err != nil {
		log.Printf("Can not open meta")
		return nil, err
	}
	f := m.File[0]
	buf := new(bytes.Buffer)
	st, err := f.Open()
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}
	_, err = io.Copy(buf, st)
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}
	return buf, nil
}

func CheckSzp(szpLocation string, hash string, certif string, pkey string) (error, *pkcs7.PKCS7) {
	szp, err := ioutil.ReadFile(szpLocation)
	if err != nil {
		return err, nil
	}
	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err, nil
	}
	err = sign.Verify()
	if err != nil {
		return err, nil
	}
	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("Unable to obtain a single signer"), nil
	}
	if hash != "" {
		hash2 := strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
		if hash != hash2 {
			fmt.Printf(hash2)
			return errors.New("Certificate hash is corrupted"), nil
		}
	}
	crt, err := tls.LoadX509KeyPair(certif, pkey)
	if err != nil {
		return err, nil
	}
	parsedCrt, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return err, nil
	}
	if bytes.Compare(parsedCrt.Raw, signer.Raw) != 0 {
		return errors.New("Certificates don't match"), nil
	}
	return nil, sign
}

func GetMeta(p *pkcs7.PKCS7) (error, []FileMeta) {
	metaSize := int32(binary.LittleEndian.Uint32(p.Content[:4]))
	bytedMeta := bytes.NewReader(p.Content[4 : metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		return err, nil
	}
	metaCompressed := readableMeta.File[0]
	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		return err, nil
	}
	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		return err, nil
	}
	err = yaml.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		return err, nil
	}
	return err, fileMetas
}

func Extract(destination string, hash string, certif string, pkey string) error {
	err, sign := CheckSzp("test.szp", hash, certif, pkey)
	if err != nil {
		return err
	}
	err, fileMetas := GetMeta(sign)
	if err != nil {
		return err
	}
	metaSize := int32(binary.LittleEndian.Uint32(sign.Content[:4]))
	archivedFiles := bytes.NewReader(sign.Content[4+metaSize:])
	err = UnarchiveFiles(archivedFiles, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}

func UnarchiveFiles(archive *bytes.Reader, fileMetas []FileMeta, destination string) error {
	zipReader, err := zip.NewReader(archive, archive.Size())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(destination, 0770); err != nil {
		fmt.Println("Couldn't create a folder to extract to")
		return err
	}
	for _, file := range zipReader.File {
		fileInfo := file.FileInfo()
		dirName, fileBaseName := filepath.Split(fileInfo.Name())
		if dirName != "" {
			if err = os.MkdirAll(filepath.Join(destination, "/", dirName), 077); err != nil {
				fmt.Println("Couldn't extract a folder")
				return err
			}
		}
		accessFile, err := file.Open()
		if err != nil {
			fmt.Println("Unable to access a file")
			return err
		}
		fileGuts, err := ioutil.ReadAll(accessFile)
		if err != nil {
			fmt.Println("Unable to read a file")
			return err
		}
		for _, metaData := range fileMetas {
			if metaData.Name == fileBaseName {
				if metaData.Hash != strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(fileGuts))) {
					return errors.New(filepath.Join(file.Name, "'s has is corrupted. The archive can't be fully unszipped"))
				}
			}
		}
		outFile, err := os.Create(filepath.Join(destination, "/", fileInfo.Name()))
		if err != nil {
			fmt.Println("Error occured when trying to create a file")
			return err
		}
		defer outFile.Close()
		if _, err = outFile.Write(fileGuts); err != nil {
			fmt.Println("A file died on surgical table")
			return err
		}
	}
	return nil
}
