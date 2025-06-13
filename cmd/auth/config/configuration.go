package config

import (
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
    "crypto/aes"
    "crypto/cipher"
    "encoding/hex"
    "io/ioutil"
	"log"
	"os"
)

type Configuration struct {
	Users    []UserConfig   `koanf:"users"`
}

type UserConfig struct {
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	Path     string `koanf:"path"`
}

var Conf Configuration

func Load(configFile string) Configuration {

    var k = koanf.New(".")

    k.Load(confmap.Provider(map[string]interface{}{}, "."), nil)

    if _, err := os.Stat(configFile); os.IsNotExist(err) {
        log.Printf("Config file %s not found, skipping config file", configFile)
    } else {
        if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
            log.Fatalf("Error loading config from file: %v", err)
        }
    }

    koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
    k.UnmarshalWithConf("Users", &Conf.Users, koanfTag)

    var password, path string
    if len(Conf.Users) > 0 {
        password = Conf.Users[0].Password
        path = Conf.Users[0].Path
        // log.Printf("Password from Conf: %s", password)
        // log.Printf("Path from Conf: %s", path)

        decrypted, err := DecryptFileContent(path, password)
        if err != nil {
            log.Printf("Failed to decrypt file: %v", err)
        } else {
            // log.Printf("Decrypted file content: %s", decrypted)
			Conf.Users[0].Password = decrypted
        }
    } else {
        log.Printf("No users found in configuration")
    }

    // Log the loaded configuration to the console
    // log.Printf("Loaded configuration: %+v", Conf)

    return Conf
}

func DecryptFileContent(path, passphrase string) (string, error) {
    encryptedData, err := ioutil.ReadFile(path)
    if err != nil {
        return "", err
    }
    // log.Printf("Loaded secret: %s", encryptedData)
    // log.Printf("Encryption key: %s", passphrase)

	keyBytes := []byte(passphrase)
	if len(keyBytes) != 32 {
		log.Printf("Key must be 32 bytes long for AES-256: %d bytes provided", len(keyBytes))
		return "", err
	}

    block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Printf("Error creating AES block cipher: %s", err)
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error setting GCM mode: %s", err)
		return "", err
	}

	decodedCipherText, err := hex.DecodeString(string(encryptedData))
	if err != nil {
		log.Printf("Error decoding HEX: %s", err)
		return "", err
	}

	decryptedData, err := gcm.Open(nil, decodedCipherText[:gcm.NonceSize()], decodedCipherText[gcm.NonceSize():], nil)
	if err != nil {
		log.Printf("Error decrypting data: %s", err)
		return "", err
	}

    return string(decryptedData), nil
}
