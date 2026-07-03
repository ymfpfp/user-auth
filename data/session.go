package data

// type Sessions struct {
// 	mu sync.RWMutex
// 	sessions map[string]map[string]any
// }
//
// func EmptySession() *Sessions {
// 	return &Sessions{
// 		sessions: make(map[string]map[string]any),
// 	}
// }
//
// // NewSessionId returns a cryptographically random 128-bit session id.
// func NewSessionId() (string, error) {
// 	b := make([]byte, 16)
// 	if _, err := rand.Read(b); err != nil {
// 		return "", err
// 	}
// 	return hex.EncodeToString(b), nil
// }
//
// func (s *Sessions) Create(data map[string]any) (string, error) {
// 	id, err := NewSessionId()
// 	if err != nil {
// 		return "", err
// 	}
//
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	s.sessions[id] = data
// 	return id, nil
// }
//
// func (s *Sessions) Get(id string) (map[string]any, bool) {
// 	s.mu.RLock()
// 	defer s.mu.RUnlock()
// 	data, ok := s.sessions[id]
// 	return data, ok
// }
//
// func (s *Sessions) Delete(id string) {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	delete(s.sessions, id)
// }
