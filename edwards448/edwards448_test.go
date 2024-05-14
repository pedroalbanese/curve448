package edwards448

import (
	"testing"

	"github.com/pedroalbanese/curve448/edwards448/field"
)

func TestSetBytes(t *testing.T) {
	v, err := new(Point).SetBytes([]byte{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x0,
	})
	if err != nil {
		t.Fatal(err)
	}

	x := new(field.Element).SetBytes([]byte{
		0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
		0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
		0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
		0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
		0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
		0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
		0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
	})
	if v.x.Equal(x) != 1 {
		t.Errorf("want %#v, got %#v", x, v.x)
	}

	y := new(field.Element).SetBytes([]byte{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	})
	if v.y.Equal(y) != 1 {
		t.Errorf("want %#v, got %#v", y, v.y)
	}
}

func TestAdd(t *testing.T) {
	t.Run("0 + 1 = 1", func(t *testing.T) {
		a := new(Point).Zero()
		b := NewIdentityPoint()
		a.Add(a, b)
		if a.Equal(b) == 0 {
			t.Errorf("got %x, want %x", a.Bytes(), b.Bytes())
		}
	})

	t.Run("0 + B = B", func(t *testing.T) {
		a := new(Point).Zero()
		b := NewGeneratorPoint()
		a.Add(a, b)
		if a.Equal(b) == 0 {
			t.Errorf("got %x, want %x", a.Bytes(), b.Bytes())
		}
	})

	t.Run("1 + (-1) = 0", func(t *testing.T) {
		a := NewIdentityPoint()
		b := NewIdentityPoint()
		b.Negate(b)
		c := new(Point).Zero()
		a.Add(a, b)
		if a.Equal(c) == 0 {
			t.Errorf("got %x, want %x", a.Bytes(), c.Bytes())
		}
	})

	t.Run("16 + (-8) = 8", func(t *testing.T) {
		a := NewIdentityPoint()
		a.Add(a, a) // 2
		a.Add(a, a) // 4
		a.Add(a, a) // 8
		a.Add(a, a) // 16
		b := NewIdentityPoint()
		b.Negate(b)
		b.Add(b, b) // -2
		b.Add(b, b) // -4
		b.Add(b, b) // -8
		c := NewIdentityPoint()
		c.Add(c, c) // 2
		c.Add(c, c) // 4
		c.Add(c, c) // 8

		a.Add(a, b)
		if a.Equal(c) == 0 {
			t.Errorf("got %x, want %x", a.Bytes(), c.Bytes())
		}
	})
}
