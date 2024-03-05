use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub bom_format: String,
    pub spec_version: String,
    pub version: i64,
    pub metadata: Metadata,
    pub components: Vec<Component2>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub tools: Vec<Tool>,
    pub component: Component,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub vendor: String,
    pub name: String,
    pub version: String,
    pub external_references: Vec<ExternalReference>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub comment: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub type_field: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub author: String,
    pub description: String,
    pub licenses: Vec<License>,
    pub purl: String,
    pub external_references: Vec<ExternalReference2>,
    pub properties: Vec<Property>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License {
    pub license: License2,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License2 {
    pub id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference2 {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub comment: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component2 {
    #[serde(rename = "type")]
    pub type_field: String,
    pub name: String,
    pub group: Option<String>,
    pub version: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub hashes: Vec<Hash>,
    #[serde(default)]
    pub licenses: Vec<License3>,
    pub purl: String,
    pub external_references: Vec<ExternalReference3>,
    pub properties: Vec<Property2>,
    pub scope: Option<String>,
    #[serde(default)]
    pub components: Vec<Component3>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash {
    pub alg: String,
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License3 {
    pub license: Option<License4>,
    pub expression: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License4 {
    pub id: Option<String>,
    pub url: Option<String>,
    pub name: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference3 {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub comment: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Property2 {
    pub name: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component3 {
    #[serde(rename = "type")]
    pub type_field: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub description: Option<String>,
    pub hashes: Vec<Hash2>,
    pub licenses: Vec<License5>,
    pub purl: String,
    pub external_references: Vec<ExternalReference4>,
    pub properties: Vec<Property3>,
    pub author: Option<String>,
    pub scope: Option<String>,
    #[serde(default)]
    pub components: Vec<Component4>,
    pub group: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash2 {
    pub alg: String,
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License5 {
    pub license: License6,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License6 {
    pub id: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference4 {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub comment: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Property3 {
    pub name: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component4 {
    #[serde(rename = "type")]
    pub type_field: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub author: Option<String>,
    pub description: String,
    pub hashes: Vec<Hash3>,
    pub licenses: Vec<License7>,
    pub purl: String,
    pub external_references: Vec<ExternalReference5>,
    pub properties: Vec<Property4>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash3 {
    pub alg: String,
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License7 {
    pub license: License8,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License8 {
    pub id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference5 {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub comment: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Property4 {
    pub name: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub ref_field: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}
