package softether

const (
	TypeInt    = 0
	TypeData   = 1
	TypeString = 2
	TypeUTF8   = 3
	TypeInt64  = 4

	maxElementName = 63
	maxElements    = 131072
	maxValues      = 65536
	maxValue       = 96 * 1024 * 1024
)

type Value struct {
	Type  byte
	Int   uint32
	Int64 uint64
	Bytes []byte
}

type Pack struct {
	elements map[string][]Value
}

func NewPack() *Pack { return &Pack{elements: make(map[string][]Value)} }

func (p *Pack) AddInt(name string, value uint32) {
	p.elements[name] = []Value{{Type: TypeInt, Int: value}}
}
func (p *Pack) AddInt64(name string, value uint64) {
	p.elements[name] = []Value{{Type: TypeInt64, Int64: value}}
}
func (p *Pack) AddString(name, value string) {
	p.elements[name] = []Value{{Type: TypeString, Bytes: []byte(value)}}
}
func (p *Pack) AddData(name string, value []byte) {
	p.elements[name] = []Value{{Type: TypeData, Bytes: append([]byte(nil), value...)}}
}
func (p *Pack) AddBool(name string, value bool) {
	if value {
		p.AddInt(name, 1)
	} else {
		p.AddInt(name, 0)
	}
}

func (p *Pack) AddValues(name string, values ...Value) {
	owned := make([]Value, len(values))
	for i, value := range values {
		owned[i] = value
		owned[i].Bytes = append([]byte(nil), value.Bytes...)
	}
	p.elements[name] = owned
}

func (p *Pack) GetInt(name string) uint32 {
	if values := p.elements[name]; len(values) != 0 && values[0].Type == TypeInt {
		return values[0].Int
	}
	return 0
}

func (p *Pack) GetString(name string) string {
	if values := p.elements[name]; len(values) != 0 && (values[0].Type == TypeString || values[0].Type == TypeUTF8) {
		return string(values[0].Bytes)
	}
	return ""
}

func (p *Pack) GetData(name string) []byte {
	if values := p.elements[name]; len(values) != 0 && values[0].Type == TypeData {
		return append([]byte(nil), values[0].Bytes...)
	}
	return nil
}

func (p *Pack) GetInt64(name string) uint64 {
	if values := p.elements[name]; len(values) != 0 && values[0].Type == TypeInt64 {
		return values[0].Int64
	}
	return 0
}

func (p *Pack) Values(name string) []Value {
	values := p.elements[name]
	owned := make([]Value, len(values))
	for i, value := range values {
		owned[i] = value
		owned[i].Bytes = append([]byte(nil), value.Bytes...)
	}
	return owned
}

func (p *Pack) Has(name string) bool { _, ok := p.elements[name]; return ok }
