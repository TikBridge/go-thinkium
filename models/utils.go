package models

import (
	"reflect"
	"strings"
)

type (
	headerField struct {
		name  string
		short string
		index int
	}

	headerFields struct {
		nameMap  map[string]*headerField
		shortMap map[string]*headerField
		names    []string
	}
)

func (fs *headerFields) get(name string) *headerField {
	n := strings.ToUpper(name)
	f := fs.nameMap[n]
	if f == nil {
		f = fs.shortMap[n]
	}
	return f
}

var (
	_headerFields     *headerFields
	_headerFullString = []string{
		"prev", "history", "parent", "parenthash", "root", "receipts", "vcc", "cashed", "hds", "confirmed",
		"era", "rrr", "rrn", "rrc", "rewarded", "comm", "nextcomm", "seed", "chains", "empty",
	}
)

func _blockHeaderFields() {
	_headerFields = &headerFields{
		nameMap:  make(map[string]*headerField),
		shortMap: make(map[string]*headerField),
	}
	typ := reflect.TypeOf((*BlockHeader)(nil)).Elem()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		short := f.Tag.Get("short")
		short = strings.TrimSpace(short)
		if short == "" {
			short = f.Name
		}
		field := &headerField{
			name:  f.Name,
			short: short,
			index: i,
		}
		_headerFields.nameMap[strings.ToUpper(f.Name)] = field
		_headerFields.shortMap[strings.ToUpper(short)] = field
		_headerFields.names = append(_headerFields.names, strings.ToUpper(f.Name))
	}
}

func init() {
	_blockHeaderFields()
}

// dynamic and static error messages
type DSError interface {
	error // static err message
	Dynamic() error
}

func EmptyBytesIfNil(bs []byte) []byte {
	if bs == nil {
		return []byte("")
	}
	return bs
}
