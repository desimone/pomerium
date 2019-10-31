package sessions

import (
	"testing"
)

// func TestState_IssuedAt(t *testing.T) {
// 	t.Parallel()
// 	tests := []struct {
// 		name    string
// 		IDToken string
// 		want    time.Time
// 		wantErr bool
// 	}{
// 		{"simple parse", "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlkzYm1qV3R4US16OW1fM1RLb0dtRWciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY3MjY4NywiZXhwIjoxNTU4Njc2Mjg3fQ.a4g8W94E7iVJhiIUmsNMwJssfx3Evi8sXeiXgXMC7kHNvftQ2CFU_LJ-dqZ5Jf61OXcrp26r7lUcTNENXuen9tyUWAiHvxk6OHTxZusdywTCY5xowpSZBO9PDWYrmmdvfhRbaKO6QVAUMkbKr1Tr8xqfoaYVXNZhERXhcVReDznI0ccbwCGrNx5oeqiL4eRdZY9eqFXi4Yfee0mkef9oyVPc2HvnpwcpM0eckYa_l_ZQChGjXVGBFIus_Ao33GbWDuc9gs-_Vp2ev4KUT2qWb7AXMCGDLx0tWI9umm7mCBi_7xnaanGKUYcVwcSrv45arllAAwzuNxO0BVw3oRWa5Q", time.Unix(1558672687, 0), false},
// 		{"bad jwt", "x.x.x-x-x", time.Time{}, true},
// 		{"malformed jwt", "x", time.Time{}, true},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := &State{IDToken: tt.IDToken}
// 			got, err := s.IssuedAt()
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("State.IssuedAt() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("State.IssuedAt() = %v, want %v", got.Format(time.RFC3339), tt.want.Format(time.RFC3339))
// 			}
// 		})
// 	}
// }

func TestState_Impersonating(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		Email              string
		Groups             []string
		ImpersonateEmail   string
		ImpersonateGroups  []string
		want               bool
		wantResponseEmail  string
		wantResponseGroups string
	}{
		{"impersonating", "actual@user.com", []string{"actual-group"}, "impersonating@user.com", []string{"impersonating-group"}, true, "impersonating@user.com", "impersonating-group"},
		{"not impersonating", "actual@user.com", []string{"actual-group"}, "", []string{}, false, "actual@user.com", "actual-group"},
		{"impersonating user only", "actual@user.com", []string{"actual-group"}, "impersonating@user.com", []string{}, true, "impersonating@user.com", "actual-group"},
		{"impersonating group only", "actual@user.com", []string{"actual-group"}, "", []string{"impersonating-group"}, true, "actual@user.com", "impersonating-group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{
				Email:             tt.Email,
				Groups:            tt.Groups,
				ImpersonateEmail:  tt.ImpersonateEmail,
				ImpersonateGroups: tt.ImpersonateGroups,
			}
			if got := s.Impersonating(); got != tt.want {
				t.Errorf("State.Impersonating() = %v, want %v", got, tt.want)
			}
			if gotEmail := s.RequestEmail(); gotEmail != tt.wantResponseEmail {
				t.Errorf("State.RequestEmail() = %v, want %v", gotEmail, tt.wantResponseEmail)
			}
			if gotGroups := s.RequestGroups(); gotGroups != tt.wantResponseGroups {
				t.Errorf("State.v() = %v, want %v", gotGroups, tt.wantResponseGroups)
			}
		})
	}
}
