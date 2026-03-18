package scanner

// Registry holds all registered language scanners.
type Registry struct {
	scanners   []Scanner
	extMap     map[string]Scanner // maps extension -> scanner
	universals []Scanner          // run on every file
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		extMap: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry.
func (r *Registry) Register(s Scanner) {
	r.scanners = append(r.scanners, s)
	for _, ext := range s.Extensions() {
		r.extMap[ext] = s
	}
}

// RegisterUniversal adds a scanner that runs on every file regardless of extension.
func (r *Registry) RegisterUniversal(s Scanner) {
	r.universals = append(r.universals, s)
}

// ForExtension returns the scanner for a given file extension, or nil.
func (r *Registry) ForExtension(ext string) Scanner {
	return r.extMap[ext]
}

// Universals returns all universal scanners.
func (r *Registry) Universals() []Scanner {
	return r.universals
}

// All returns all registered scanners.
func (r *Registry) All() []Scanner {
	return r.scanners
}
