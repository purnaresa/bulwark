package rsa

import (
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/purnaresa/bulwark/utils"
)

var alicePrivKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

var alicePubKey = `-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnB7b4EcPH9cLPhyqxmmI
Mi6ARDIMbgsWO9W5Q+PsOMEWVCGvpE+Xhhnl8QWdjPFJ3DCOl9nwruWCLDY0D40u
Z3QwpJkpEwKokhQjw3aKYGmuX6A5g2/Wagmmx7BMRZSvSc2fhzIHN1oZoZ7SFnae
aizts1nKGKuzXVHebA6cQrURAzGJvIWegjZ36PcoPlbMCiAfsTKuXqKH50bjwC7y
lATqOJG2qjdCzYrfYecpW7fLgArLZ20gwTtrx5xqFJp7nfej78g//AUlMPhkS4+I
VZI2I6XziGEIMAPFgY7nn9YM/Rxlu1VWKMGOPBmQZfImbMBuLf4Og3rEfTmn/Tyt
55+g5iB6yd+kfpWDEhxV6y8uT5ABvfwRRtInKxYQlAcbzQa3KcD3J9J3Kzag9Wm3
Lne3kDsyRZNBnTWM5fBr5wrqqk8B2TRr8iNC6sfmCBTgdKz9je+2Ujhdg7JNuvXe
c4rAaX77Yylsz1R/zqMAq0zAhfo0YLsLwB1TKnnzt26kLvOvqu1f8DLMo8ZzyYr8
PwlCADyot/ZTuHJJnCmkHC4+wcb0aKPSXE7URDeWqyGaldkOLAwI74gWxTQXpyTQ
tCIT3DDwLAE0iQt3YcNOjtcCrQI0plFSWBWmyPYCg4aqsNkUpIfKTNTAa4PoHcdJ
MLNLCZynmcufzcafMuo8J6kCAwEAAQ==
-----END RSA PUBLIC KEY-----
`

func TestClient_Encrypt(t *testing.T) {
	privateKey, _ := utils.ReadPrivateKey([]byte(alicePrivKey))
	publicKey, _ := utils.ReadPublicKey([]byte(alicePubKey))

	type fields struct {
		Private *rsa.PrivateKey
		Publics *rsa.PublicKey
	}
	type args struct {
		plainData []byte
		target    string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy case",
			fields: fields{
				Private: privateKey,
				Publics: publicKey,
			},
			args: args{
				plainData: []byte("Hello, my name is alice"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(
				tt.fields.Private,
				tt.fields.Publics)

			gotCipherData, err := c.Encrypt(tt.args.plainData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotPlain, err := c.Decrypt([]byte(gotCipherData))
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.DecryptToString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotPlain, tt.args.plainData) {
				t.Errorf("Encryption Failed = %v, want %v", gotPlain, tt.args.plainData)
			}
		})
	}
}
