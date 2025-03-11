package v1

type subject interface {
	GetName() string
	GetUri() string
	GetDigest() map[string]string
}

func NewResourceDescriptor() *ResourceDescriptor {
	return &ResourceDescriptor{}
}

// FromSubject
func (rd *ResourceDescriptor) FromSubject(s subject) *ResourceDescriptor {
	if s != nil {
		rd.Digest = s.GetDigest()
		rd.Name = s.GetName()
		rd.Uri = s.GetUri()
	}
	return rd
}
