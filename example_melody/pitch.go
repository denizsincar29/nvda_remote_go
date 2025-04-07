package main

import (
	"math"
	"sync"
	"time"
)

func pitchToFreq(midinote int) float64 {
	st := midinote - 69 // 69 is the MIDI note number for A4
	return 440 * math.Pow(2, float64(st)/12)
}

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

func noteToMidi(note int, octave int) int {
	// Convert note and octave to MIDI note number
	return (octave+1)*12 + note
}

func NoteToFreq(note int, octave int) float64 {
	// Convert note and octave to MIDI note number
	midinote := noteToMidi(note, octave)
	return pitchToFreq(midinote)
}

type Note struct {
	Pitch    int // 0-11
	Octave   int // 0-8
	Duration int // in milliseconds
	Pause    int // in milliseconds
}

func (n Note) ToFD() FreqDur {
	// Convert note to frequency and duration
	freq := NoteToFreq(n.Pitch, n.Octave)
	return FreqDur{freq, n.Duration}
}

var notes = []Note{
	{NOTE_C, 5, 300, 100},
	{NOTE_G, 4, 150, 50},
	{NOTE_G, 4, 150, 50},
	{NOTE_A, 4, 300, 100},
	{NOTE_G, 4, 400, 400},
	{NOTE_B, 4, 300, 100},
	{NOTE_C, 5, 500, 0},
}

type FreqDur struct {
	Freq     float64 // frequency in Hz
	Duration int     // duration in milliseconds
}

type NoteMaker struct {
	Running   bool
	RunningMu sync.Mutex
	Ch        chan FreqDur
}

func (n *NoteMaker) Start() {
	// start a goroutine to play the notes
	n.RunningMu.Lock()
	defer n.RunningMu.Unlock()
	if n.Running {
		return
	}
	n.Running = true
	go func() {
		for _, note := range notes {
			// convert note to frequency and duration
			fd := note.ToFD()
			n.Ch <- fd
			time.Sleep(time.Duration(note.Duration) * time.Millisecond)
			time.Sleep(time.Duration(note.Pause) * time.Millisecond)
		}
		// set the running flag to false when done
		n.RunningMu.Lock()
		defer n.RunningMu.Unlock()
		n.Running = false
	}()

}

// NewNoteMaker creates a new NoteMaker instance with a channel for frequency and duration.
func NewNoteMaker() *NoteMaker {
	return &NoteMaker{
		Ch: make(chan FreqDur),
	}
}
