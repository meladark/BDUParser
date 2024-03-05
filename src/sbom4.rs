use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: Option<String>,
    pub version: i32,
    pub metadata: Option<Metadata>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub timestamp: Option<String>,
    pub tool: Option<Vec<Tool>>,
    pub authors: Option<Vec<Author>>,
    pub component: Option<Component>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub hashes: Option<Vec<Hash>>,
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash {
    pub alg: String,
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference {
    pub url: String,
    pub comment: Option<String>,
    #[serde(rename = "type")]
    pub type_field: String,
    pub hashes: Option<Vec<Hash>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Author {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "mime-type")]
    pub mime_type: Option<String>,
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    pub supplier: Option<Supplier>,
    pub author: Option<String>,
    pub publisher: Option<String>,
    pub group: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub scope: Option<String>, // TODO: add enum
    pub hashes: Option<Vec<Hash>>,
    // TODO: Add lic
    pub copyright: Option<String>,
    pub cpe: Option<String>,
    pub purl: Option<String>,
    pub swid: Option<Swid>,
    pub modified: Option<bool>, //Deprecated
                                //TODO: Add pedigree
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Supplier {
    pub name: Option<String>,
    pub url: Option<Vec<String>>,
    pub contact: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Swid {
    pub tag_id: String,
    pub name: String,
    pub version: Option<String>,
    pub tag_version: Option<i32>,
    pub patch: Option<bool>,
    pub text: Option<Text>,
    pub url: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Text {
    content_type: Option<String>,
    encoding: Option<String>,
    content: String,
}
