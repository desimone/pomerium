package cryptutil

import (
	"crypto/tls"
	"testing"
)

func TestTLSConfigFromBase64(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{"good",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
			false},
		{"bad cert",
			"!=",
			"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
			true},
		{"bad key",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			"!=",
			true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TLSConfigFromBase64(tt.cert, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("TLSConfigFromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestTLSConfigFromFile(t *testing.T) {
	cfg, err := TLSConfigFromFile("testdata/example-cert.pem", "testdata/example-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", ":0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = listener
}
