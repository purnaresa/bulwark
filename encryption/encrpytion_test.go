package encryption

import (
	"testing"
)

func TestClient_generateRandomString(t *testing.T) {
	c := NewClient()
	type args struct {
		length int
	}
	tests := []struct {
		name       string
		c          *Client
		args       args
		wantResult int
	}{
		{
			name: "happy case",
			c:    c,
			args: args{
				length: 32,
			},
			wantResult: 32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := tt.c.GenerateRandomString(tt.args.length)
			if len(gotResult) != tt.wantResult {
				t.Errorf("Client.generateRandomString() = len(%v), want %v", gotResult, tt.wantResult)
			}
		})
	}
}
