package crypto

import (
	"testing"
)

func TestSignDefault(t *testing.T) {
	privateKey, publicKey, _ := GenerateKeyPair()

	type args struct {
		plaintext  []byte
		privateKey []byte
		publicKey  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				plaintext:  []byte("hello, i want to sign this doc"),
				privateKey: privateKey,
				publicKey:  publicKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSignature, err := SignDefault(tt.args.plaintext, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignDefault() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			errVerify := VerifyDefault(tt.args.plaintext, tt.args.publicKey, gotSignature)
			if (errVerify != nil) != tt.wantErr {
				t.Errorf("SignDefault() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
