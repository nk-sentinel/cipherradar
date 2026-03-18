package scanner

// Registry holds all registered language scanners.
type Registry struct {
	scanners []Scanner
	extMap   map[string]Scanner // maps extension -> scanner
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

// ForExtension returns the scanner for a given file extension, or nil.
func (r *Registry) ForExtension(ext string) Scanner {
	return r.extMap[ext]
}

// All returns all registered scanners.
func (r *Registry) All() []Scanner {
	return r.scanners
}
