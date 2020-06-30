package main

type NtlmChallenge struct {
	Signature [8]byte
	MsgType uint32
	TargetNameLen uint16
	TargetNameMaxLen uint16
	TargetNameBufferOffset uint32
	NegotiateFlags [4]byte
	ServerChallenge [8]byte
	Reserved [8]byte
	TargetInfoBytes [8]byte
}
