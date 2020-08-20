package crypto

import (
	"encoding/pem"
	"reflect"
	"testing"
)

func TestClient_Encrypt(t *testing.T) {
	type args struct {
		plainData []byte
		target    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy test",
			args: args{
				plainData: []byte("hello, i am your bulwark"),
				target:    "test_user",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			privateKey, publicKey, err := GenerateKeyPair()
			publicKeys := make(map[string][]byte)
			publicKeys["test_user"] = publicKey

			c, _ := New(privateKey, publicKeys)

			gotCipherData, err := c.Encrypt(tt.args.plainData, tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			plainText, _ := c.Decrypt(gotCipherData)

			if !reflect.DeepEqual(tt.args.plainData, plainText) {
				t.Errorf("Client.Encrypt() = %v, want %v", tt.args.plainData, plainText)
			}
		})
	}
}

func TestGenerateKeyPairInPEM(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "Happy Test", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrivateKey, gotPublicKey, gotPrivateKeyPem, gotPublicKeyPem, err := GenerateKeyPairInPEM()
			privateKey, _ := pem.Decode(gotPrivateKeyPem)
			publicKey, _ := pem.Decode(gotPublicKeyPem)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPairInPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPrivateKey, privateKey.Bytes) {
				t.Errorf("GenerateKeyPairInPEM() gotPrivateKey = %v, want %v", gotPrivateKey, privateKey)
			}
			if !reflect.DeepEqual(gotPublicKey, publicKey.Bytes) {
				t.Errorf("GenerateKeyPairInPEM() gotPublicKey = %v, want %v", gotPublicKey, publicKey)
			}

		})
	}
}

func TestEncryptDefault(t *testing.T) {
	privateKey, publicKey, _ := GenerateKeyPair()

	type args struct {
		plainData  []byte
		publicKey  []byte
		privateKey []byte
	}
	tests := []struct {
		name           string
		args           args
		wantCipherData string
		wantErr        bool
	}{
		{
			name: "happy",
			args: args{
				plainData:  []byte("ultraman 80"),
				publicKey:  publicKey,
				privateKey: privateKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCipherData, err := EncryptDefault(tt.args.plainData, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptDefault() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			plainText, err := DecryptDefault(gotCipherData, tt.args.privateKey)
			if !reflect.DeepEqual(tt.args.plainData, plainText) {
				t.Errorf("EncryptDefault() = %v, want %v", plainText, tt.args.plainData)
			}
		})
	}
}
