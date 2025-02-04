package oscal

// Temporary to be switched to go-oscal
type Catalog struct {
	UUID     string
	Metadata Metadata
	Groups   []Group
}

type Metadata struct {
	Title   string
	Version string
}

type Group struct {
	ID       string
	Class    string
	Title    string
	Controls []Control
}

type Control struct {
	ID    string
	Class string
	Title string
}
