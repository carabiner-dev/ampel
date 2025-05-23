// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// This type was lifted from the intoto project to avoid the pain of
// linking to external protos.
// https://github.com/in-toto/attestation/blob/main/protos/in_toto_attestation/v1/resource_descriptor.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: intoto.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ResourceDescriptor is the official in-toto ResourceDescriptor definition
// but mirrored in the AMPEL API.
type ResourceDescriptor struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Name             string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Uri              string                 `protobuf:"bytes,2,opt,name=uri,proto3" json:"uri,omitempty"`
	Digest           map[string]string      `protobuf:"bytes,3,rep,name=digest,proto3" json:"digest,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Content          []byte                 `protobuf:"bytes,4,opt,name=content,proto3" json:"content,omitempty"`
	DownloadLocation string                 `protobuf:"bytes,5,opt,name=download_location,json=downloadLocation,proto3" json:"download_location,omitempty"`
	MediaType        string                 `protobuf:"bytes,6,opt,name=media_type,json=mediaType,proto3" json:"media_type,omitempty"`
	Annotations      *structpb.Struct       `protobuf:"bytes,7,opt,name=annotations,proto3" json:"annotations,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ResourceDescriptor) Reset() {
	*x = ResourceDescriptor{}
	mi := &file_intoto_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ResourceDescriptor) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceDescriptor) ProtoMessage() {}

func (x *ResourceDescriptor) ProtoReflect() protoreflect.Message {
	mi := &file_intoto_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceDescriptor.ProtoReflect.Descriptor instead.
func (*ResourceDescriptor) Descriptor() ([]byte, []int) {
	return file_intoto_proto_rawDescGZIP(), []int{0}
}

func (x *ResourceDescriptor) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ResourceDescriptor) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *ResourceDescriptor) GetDigest() map[string]string {
	if x != nil {
		return x.Digest
	}
	return nil
}

func (x *ResourceDescriptor) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *ResourceDescriptor) GetDownloadLocation() string {
	if x != nil {
		return x.DownloadLocation
	}
	return ""
}

func (x *ResourceDescriptor) GetMediaType() string {
	if x != nil {
		return x.MediaType
	}
	return ""
}

func (x *ResourceDescriptor) GetAnnotations() *structpb.Struct {
	if x != nil {
		return x.Annotations
	}
	return nil
}

var File_intoto_proto protoreflect.FileDescriptor

const file_intoto_proto_rawDesc = "" +
	"\n" +
	"\fintoto.proto\x12\bampel.v1\x1a\x1cgoogle/protobuf/struct.proto\"\xd8\x02\n" +
	"\x12ResourceDescriptor\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x10\n" +
	"\x03uri\x18\x02 \x01(\tR\x03uri\x12@\n" +
	"\x06digest\x18\x03 \x03(\v2(.ampel.v1.ResourceDescriptor.DigestEntryR\x06digest\x12\x18\n" +
	"\acontent\x18\x04 \x01(\fR\acontent\x12+\n" +
	"\x11download_location\x18\x05 \x01(\tR\x10downloadLocation\x12\x1d\n" +
	"\n" +
	"media_type\x18\x06 \x01(\tR\tmediaType\x129\n" +
	"\vannotations\x18\a \x01(\v2\x17.google.protobuf.StructR\vannotations\x1a9\n" +
	"\vDigestEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01B\x87\x01\n" +
	"\fcom.ampel.v1B\vIntotoProtoP\x01Z)github.com/carabiner-dev/ampel/pkg/api/v1\xa2\x02\x03AXX\xaa\x02\bAmpel.V1\xca\x02\bAmpel\\V1\xe2\x02\x14Ampel\\V1\\GPBMetadata\xea\x02\tAmpel::V1b\x06proto3"

var (
	file_intoto_proto_rawDescOnce sync.Once
	file_intoto_proto_rawDescData []byte
)

func file_intoto_proto_rawDescGZIP() []byte {
	file_intoto_proto_rawDescOnce.Do(func() {
		file_intoto_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_intoto_proto_rawDesc), len(file_intoto_proto_rawDesc)))
	})
	return file_intoto_proto_rawDescData
}

var file_intoto_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_intoto_proto_goTypes = []any{
	(*ResourceDescriptor)(nil), // 0: ampel.v1.ResourceDescriptor
	nil,                        // 1: ampel.v1.ResourceDescriptor.DigestEntry
	(*structpb.Struct)(nil),    // 2: google.protobuf.Struct
}
var file_intoto_proto_depIdxs = []int32{
	1, // 0: ampel.v1.ResourceDescriptor.digest:type_name -> ampel.v1.ResourceDescriptor.DigestEntry
	2, // 1: ampel.v1.ResourceDescriptor.annotations:type_name -> google.protobuf.Struct
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_intoto_proto_init() }
func file_intoto_proto_init() {
	if File_intoto_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_intoto_proto_rawDesc), len(file_intoto_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_intoto_proto_goTypes,
		DependencyIndexes: file_intoto_proto_depIdxs,
		MessageInfos:      file_intoto_proto_msgTypes,
	}.Build()
	File_intoto_proto = out.File
	file_intoto_proto_goTypes = nil
	file_intoto_proto_depIdxs = nil
}
