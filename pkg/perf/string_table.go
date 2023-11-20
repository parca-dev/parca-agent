package perf

type entry struct {
	offset uint32
	length uint32
}

type StringTable struct {
	data    []byte
	entries []entry

	dict map[string]int
}

func NewStringTable(dataCapacity, entriesCapacity int) *StringTable {
	return &StringTable{
		data:    make([]byte, 0, dataCapacity),
		entries: make([]entry, 0, entriesCapacity),
		dict:    make(map[string]int),
	}
}

func (t *StringTable) AddOrGet(s string) int {
	if i, ok := t.dict[s]; ok {
		return i
	}

	// double the capacity until we have enough
	for len(t.data)+len(s) > cap(t.data) {
		newData := make([]byte, cap(t.data)*2)
		copy(newData, t.data)
		t.data = newData[:len(t.data)]
	}
	offset := uint32(len(t.data))
	t.data = append(t.data, s...)
	t.entries = append(t.entries, entry{
		offset: offset,
		length: uint32(len(s)),
	})
	i := len(t.entries) - 1
	t.dict[s] = i
	return i
}

func (t *StringTable) Get(i int) string {
	return string(t.GetBytes(i))
}

func (t *StringTable) GetBytes(i int) []byte {
	e := t.entries[i]
	return t.data[e.offset : e.offset+e.length]
}
