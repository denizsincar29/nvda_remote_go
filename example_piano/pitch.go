package main

import (
	"math"
)

const (
	NOTE_C  = 0
	NOTE_Cs = 1
	NOTE_DB = 1
	NOTE_D  = 2
	NOTE_Ds = 3
	NOTE_Eb = 3
	NOTE_E  = 4
	NOTE_F  = 5
	NOTE_Fs = 6
	NOTE_Gb = 6
	NOTE_G  = 7
	NOTE_Gs = 8
	NOTE_Ab = 8
	NOTE_A  = 9
	NOTE_As = 10
	NOTE_Bb = 10
	NOTE_B  = 11
)

type Note struct {
	Pitch  int // 0-11
	Octave int // 0-8
}

func (n *Note) ToFreq() float64 {
	return 440.0 * math.Pow(2, float64(n.Pitch+(n.Octave+1)*12-69)/12.0)
}

// map keyboard keys to MIDI notes
var keyToNote = map[string]Note{
	"a":     {NOTE_C, 4},
	"w":     {NOTE_Cs, 4},
	"s":     {NOTE_D, 4},
	"e":     {NOTE_Ds, 4},
	"d":     {NOTE_E, 4},
	"f":     {NOTE_F, 4},
	"t":     {NOTE_Fs, 4},
	"g":     {NOTE_G, 4},
	"y":     {NOTE_Gs, 4},
	"h":     {NOTE_A, 4},
	"u":     {NOTE_As, 4},
	"j":     {NOTE_B, 4},
	"k":     {NOTE_C, 5},
	"o":     {NOTE_Cs, 5},
	"l":     {NOTE_D, 5},
	"p":     {NOTE_Ds, 5},
	";":     {NOTE_E, 5},
	"'":     {NOTE_F, 5},
	"[":     {NOTE_Fs, 5},
	"enter": {NOTE_G, 5},
	"]":     {NOTE_Gs, 5},
	"\\":    {NOTE_Gs, 5},
}

// GetNote returns the note for the given key.
func GetNote(key string) (Note, bool) {
	note, ok := keyToNote[key]
	return note, ok
}
