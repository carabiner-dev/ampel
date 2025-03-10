// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        (unknown)
// source: provenance-v1.1.0.proto

package v11

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

type Provenance struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	BuildDefinition *BuildDefinition       `protobuf:"bytes,1,opt,name=build_definition,json=buildDefinition,proto3" json:"build_definition,omitempty"`
	RunDetails      *RunDetails            `protobuf:"bytes,2,opt,name=run_details,json=runDetails,proto3" json:"run_details,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *Provenance) Reset() {
	*x = Provenance{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Provenance) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Provenance) ProtoMessage() {}

func (x *Provenance) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Provenance.ProtoReflect.Descriptor instead.
func (*Provenance) Descriptor() ([]byte, []int) {
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{0}
}

func (x *Provenance) GetBuildDefinition() *BuildDefinition {
	if x != nil {
		return x.BuildDefinition
	}
	return nil
}

func (x *Provenance) GetRunDetails() *RunDetails {
	if x != nil {
		return x.RunDetails
	}
	return nil
}

type BuildDefinition struct {
	state                protoimpl.MessageState `protogen:"open.v1"`
	BuildType            string                 `protobuf:"bytes,1,opt,name=build_type,json=buildType,proto3" json:"build_type,omitempty"`
	ExternalParameters   *structpb.Struct       `protobuf:"bytes,2,opt,name=external_parameters,json=externalParameters,proto3" json:"external_parameters,omitempty"`
	InternalParameters   *structpb.Struct       `protobuf:"bytes,3,opt,name=internal_parameters,json=internalParameters,proto3" json:"internal_parameters,omitempty"`
	ResolvedDependencies []*ResourceDescriptor  `protobuf:"bytes,4,rep,name=resolved_dependencies,json=resolvedDependencies,proto3" json:"resolved_dependencies,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *BuildDefinition) Reset() {
	*x = BuildDefinition{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BuildDefinition) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BuildDefinition) ProtoMessage() {}

func (x *BuildDefinition) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BuildDefinition.ProtoReflect.Descriptor instead.
func (*BuildDefinition) Descriptor() ([]byte, []int) {
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{1}
}

func (x *BuildDefinition) GetBuildType() string {
	if x != nil {
		return x.BuildType
	}
	return ""
}

func (x *BuildDefinition) GetExternalParameters() *structpb.Struct {
	if x != nil {
		return x.ExternalParameters
	}
	return nil
}

func (x *BuildDefinition) GetInternalParameters() *structpb.Struct {
	if x != nil {
		return x.InternalParameters
	}
	return nil
}

func (x *BuildDefinition) GetResolvedDependencies() []*ResourceDescriptor {
	if x != nil {
		return x.ResolvedDependencies
	}
	return nil
}

type ResourceDescriptor struct {
	state            protoimpl.MessageState     `protogen:"open.v1"`
	Uri              string                     `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	Digest           map[string]string          `protobuf:"bytes,2,rep,name=digest,proto3" json:"digest,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Name             string                     `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	DownloadLocation string                     `protobuf:"bytes,4,opt,name=download_location,json=downloadLocation,proto3" json:"download_location,omitempty"`
	MediaType        string                     `protobuf:"bytes,5,opt,name=media_type,json=mediaType,proto3" json:"media_type,omitempty"`
	Content          []byte                     `protobuf:"bytes,6,opt,name=content,proto3" json:"content,omitempty"`
	Annotations      map[string]*structpb.Value `protobuf:"bytes,7,rep,name=annotations,proto3" json:"annotations,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ResourceDescriptor) Reset() {
	*x = ResourceDescriptor{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ResourceDescriptor) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceDescriptor) ProtoMessage() {}

func (x *ResourceDescriptor) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[2]
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
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{2}
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

func (x *ResourceDescriptor) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
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

func (x *ResourceDescriptor) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *ResourceDescriptor) GetAnnotations() map[string]*structpb.Value {
	if x != nil {
		return x.Annotations
	}
	return nil
}

type RunDetails struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Builder       *Builder               `protobuf:"bytes,1,opt,name=builder,proto3" json:"builder,omitempty"`
	Metadata      *BuildMetadata         `protobuf:"bytes,2,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Byproducts    []*ResourceDescriptor  `protobuf:"bytes,3,rep,name=byproducts,proto3" json:"byproducts,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RunDetails) Reset() {
	*x = RunDetails{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RunDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RunDetails) ProtoMessage() {}

func (x *RunDetails) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RunDetails.ProtoReflect.Descriptor instead.
func (*RunDetails) Descriptor() ([]byte, []int) {
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{3}
}

func (x *RunDetails) GetBuilder() *Builder {
	if x != nil {
		return x.Builder
	}
	return nil
}

func (x *RunDetails) GetMetadata() *BuildMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *RunDetails) GetByproducts() []*ResourceDescriptor {
	if x != nil {
		return x.Byproducts
	}
	return nil
}

type Builder struct {
	state               protoimpl.MessageState `protogen:"open.v1"`
	Id                  string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Version             map[string]string      `protobuf:"bytes,2,rep,name=version,proto3" json:"version,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	BuilderDependencies []*ResourceDescriptor  `protobuf:"bytes,3,rep,name=builder_dependencies,json=builderDependencies,proto3" json:"builder_dependencies,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *Builder) Reset() {
	*x = Builder{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Builder) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Builder) ProtoMessage() {}

func (x *Builder) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Builder.ProtoReflect.Descriptor instead.
func (*Builder) Descriptor() ([]byte, []int) {
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{4}
}

func (x *Builder) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Builder) GetVersion() map[string]string {
	if x != nil {
		return x.Version
	}
	return nil
}

func (x *Builder) GetBuilderDependencies() []*ResourceDescriptor {
	if x != nil {
		return x.BuilderDependencies
	}
	return nil
}

type BuildMetadata struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	InvocationId  string                 `protobuf:"bytes,1,opt,name=invocation_id,json=invocationId,proto3" json:"invocation_id,omitempty"`
	StartedOn     *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=started_on,json=startedOn,proto3" json:"started_on,omitempty"`
	FinishedOn    *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=finished_on,json=finishedOn,proto3" json:"finished_on,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BuildMetadata) Reset() {
	*x = BuildMetadata{}
	mi := &file_provenance_v1_1_0_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BuildMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BuildMetadata) ProtoMessage() {}

func (x *BuildMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_provenance_v1_1_0_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BuildMetadata.ProtoReflect.Descriptor instead.
func (*BuildMetadata) Descriptor() ([]byte, []int) {
	return file_provenance_v1_1_0_proto_rawDescGZIP(), []int{5}
}

func (x *BuildMetadata) GetInvocationId() string {
	if x != nil {
		return x.InvocationId
	}
	return ""
}

func (x *BuildMetadata) GetStartedOn() *timestamppb.Timestamp {
	if x != nil {
		return x.StartedOn
	}
	return nil
}

func (x *BuildMetadata) GetFinishedOn() *timestamppb.Timestamp {
	if x != nil {
		return x.FinishedOn
	}
	return nil
}

var File_provenance_v1_1_0_proto protoreflect.FileDescriptor

var file_provenance_v1_1_0_proto_rawDesc = string([]byte{
	0x0a, 0x17, 0x70, 0x72, 0x6f, 0x76, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x76, 0x31, 0x2e,
	0x31, 0x2e, 0x30, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x73, 0x6c, 0x73, 0x61, 0x2e,
	0x76, 0x31, 0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x89, 0x01, 0x0a, 0x0a, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x6e, 0x61, 0x6e, 0x63,
	0x65, 0x12, 0x44, 0x0a, 0x10, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e,
	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x73, 0x6c,
	0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x65, 0x66, 0x69,
	0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x65, 0x66,
	0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x35, 0x0a, 0x0b, 0x72, 0x75, 0x6e, 0x5f, 0x64,
	0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x73,
	0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x52, 0x75, 0x6e, 0x44, 0x65, 0x74, 0x61, 0x69,
	0x6c, 0x73, 0x52, 0x0a, 0x72, 0x75, 0x6e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x97,
	0x02, 0x0a, 0x0f, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x48, 0x0a, 0x13, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x70, 0x61,
	0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x12, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x12, 0x48, 0x0a, 0x13, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65,
	0x72, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63,
	0x74, 0x52, 0x12, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x65, 0x74, 0x65, 0x72, 0x73, 0x12, 0x51, 0x0a, 0x15, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65,
	0x64, 0x5f, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x6f, 0x72, 0x52, 0x14, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x64, 0x44, 0x65, 0x70, 0x65,
	0x6e, 0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x22, 0xc6, 0x03, 0x0a, 0x12, 0x52, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x12,
	0x10, 0x0a, 0x03, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72,
	0x69, 0x12, 0x40, 0x0a, 0x06, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x28, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x52, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e,
	0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x64, 0x69, 0x67,
	0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2b, 0x0a, 0x11, 0x64, 0x6f, 0x77, 0x6e, 0x6c,
	0x6f, 0x61, 0x64, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x10, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x4c, 0x6f, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x4f, 0x0a,
	0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x52, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72,
	0x2e, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x0b, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x39,
	0x0a, 0x0b, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x56, 0x0a, 0x10, 0x41, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x2c, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0xac, 0x01, 0x0a, 0x0a, 0x52, 0x75, 0x6e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x12, 0x2b, 0x0a, 0x07, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x11, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x42, 0x75, 0x69,
	0x6c, 0x64, 0x65, 0x72, 0x52, 0x07, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x12, 0x33, 0x0a,
	0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x12, 0x3c, 0x0a, 0x0a, 0x62, 0x79, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31,
	0x31, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x6f, 0x72, 0x52, 0x0a, 0x62, 0x79, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73,
	0x22, 0xe0, 0x01, 0x0a, 0x07, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x38, 0x0a, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e,
	0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72,
	0x2e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x4f, 0x0a, 0x14, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65,
	0x72, 0x5f, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e, 0x76, 0x31, 0x31, 0x2e,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x6f, 0x72, 0x52, 0x13, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x44, 0x65, 0x70, 0x65, 0x6e,
	0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x1a, 0x3a, 0x0a, 0x0c, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x22, 0xac, 0x01, 0x0a, 0x0d, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x23, 0x0a, 0x0d, 0x69, 0x6e, 0x76, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x69, 0x6e,
	0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x39, 0x0a, 0x0a, 0x73, 0x74,
	0x61, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72,
	0x74, 0x65, 0x64, 0x4f, 0x6e, 0x12, 0x3b, 0x0a, 0x0b, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65,
	0x64, 0x5f, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64,
	0x4f, 0x6e, 0x42, 0xae, 0x01, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x6c, 0x73, 0x61, 0x2e,
	0x76, 0x31, 0x31, 0x42, 0x13, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x56,
	0x31, 0x31, 0x30, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x48, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x61, 0x72, 0x61, 0x62, 0x69, 0x6e, 0x65, 0x72,
	0x2d, 0x64, 0x65, 0x76, 0x2f, 0x61, 0x6d, 0x70, 0x65, 0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x66,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x73, 0x2f, 0x70, 0x72, 0x65, 0x64, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x2f, 0x73, 0x6c, 0x73, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65,
	0x2f, 0x76, 0x31, 0x31, 0xa2, 0x02, 0x03, 0x53, 0x58, 0x58, 0xaa, 0x02, 0x08, 0x53, 0x6c, 0x73,
	0x61, 0x2e, 0x56, 0x31, 0x31, 0xca, 0x02, 0x08, 0x53, 0x6c, 0x73, 0x61, 0x5c, 0x56, 0x31, 0x31,
	0xe2, 0x02, 0x14, 0x53, 0x6c, 0x73, 0x61, 0x5c, 0x56, 0x31, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x09, 0x53, 0x6c, 0x73, 0x61, 0x3a, 0x3a,
	0x56, 0x31, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_provenance_v1_1_0_proto_rawDescOnce sync.Once
	file_provenance_v1_1_0_proto_rawDescData []byte
)

func file_provenance_v1_1_0_proto_rawDescGZIP() []byte {
	file_provenance_v1_1_0_proto_rawDescOnce.Do(func() {
		file_provenance_v1_1_0_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_provenance_v1_1_0_proto_rawDesc), len(file_provenance_v1_1_0_proto_rawDesc)))
	})
	return file_provenance_v1_1_0_proto_rawDescData
}

var file_provenance_v1_1_0_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_provenance_v1_1_0_proto_goTypes = []any{
	(*Provenance)(nil),            // 0: slsa.v11.Provenance
	(*BuildDefinition)(nil),       // 1: slsa.v11.BuildDefinition
	(*ResourceDescriptor)(nil),    // 2: slsa.v11.ResourceDescriptor
	(*RunDetails)(nil),            // 3: slsa.v11.RunDetails
	(*Builder)(nil),               // 4: slsa.v11.Builder
	(*BuildMetadata)(nil),         // 5: slsa.v11.BuildMetadata
	nil,                           // 6: slsa.v11.ResourceDescriptor.DigestEntry
	nil,                           // 7: slsa.v11.ResourceDescriptor.AnnotationsEntry
	nil,                           // 8: slsa.v11.Builder.VersionEntry
	(*structpb.Struct)(nil),       // 9: google.protobuf.Struct
	(*timestamppb.Timestamp)(nil), // 10: google.protobuf.Timestamp
	(*structpb.Value)(nil),        // 11: google.protobuf.Value
}
var file_provenance_v1_1_0_proto_depIdxs = []int32{
	1,  // 0: slsa.v11.Provenance.build_definition:type_name -> slsa.v11.BuildDefinition
	3,  // 1: slsa.v11.Provenance.run_details:type_name -> slsa.v11.RunDetails
	9,  // 2: slsa.v11.BuildDefinition.external_parameters:type_name -> google.protobuf.Struct
	9,  // 3: slsa.v11.BuildDefinition.internal_parameters:type_name -> google.protobuf.Struct
	2,  // 4: slsa.v11.BuildDefinition.resolved_dependencies:type_name -> slsa.v11.ResourceDescriptor
	6,  // 5: slsa.v11.ResourceDescriptor.digest:type_name -> slsa.v11.ResourceDescriptor.DigestEntry
	7,  // 6: slsa.v11.ResourceDescriptor.annotations:type_name -> slsa.v11.ResourceDescriptor.AnnotationsEntry
	4,  // 7: slsa.v11.RunDetails.builder:type_name -> slsa.v11.Builder
	5,  // 8: slsa.v11.RunDetails.metadata:type_name -> slsa.v11.BuildMetadata
	2,  // 9: slsa.v11.RunDetails.byproducts:type_name -> slsa.v11.ResourceDescriptor
	8,  // 10: slsa.v11.Builder.version:type_name -> slsa.v11.Builder.VersionEntry
	2,  // 11: slsa.v11.Builder.builder_dependencies:type_name -> slsa.v11.ResourceDescriptor
	10, // 12: slsa.v11.BuildMetadata.started_on:type_name -> google.protobuf.Timestamp
	10, // 13: slsa.v11.BuildMetadata.finished_on:type_name -> google.protobuf.Timestamp
	11, // 14: slsa.v11.ResourceDescriptor.AnnotationsEntry.value:type_name -> google.protobuf.Value
	15, // [15:15] is the sub-list for method output_type
	15, // [15:15] is the sub-list for method input_type
	15, // [15:15] is the sub-list for extension type_name
	15, // [15:15] is the sub-list for extension extendee
	0,  // [0:15] is the sub-list for field type_name
}

func init() { file_provenance_v1_1_0_proto_init() }
func file_provenance_v1_1_0_proto_init() {
	if File_provenance_v1_1_0_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_provenance_v1_1_0_proto_rawDesc), len(file_provenance_v1_1_0_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_provenance_v1_1_0_proto_goTypes,
		DependencyIndexes: file_provenance_v1_1_0_proto_depIdxs,
		MessageInfos:      file_provenance_v1_1_0_proto_msgTypes,
	}.Build()
	File_provenance_v1_1_0_proto = out.File
	file_provenance_v1_1_0_proto_goTypes = nil
	file_provenance_v1_1_0_proto_depIdxs = nil
}
