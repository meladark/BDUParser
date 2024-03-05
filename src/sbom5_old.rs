use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub bom_format: String,
    pub spec_version: Option<String>,
    pub serial_number: String,
    pub version: i64,
    pub metadata: Metadata,
    pub components: Vec<Component3>,
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
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub scope: String,
    pub purl: String,
    pub components: Vec<Component2>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component2 {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component3 {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub scope: String,
    #[serde(default)]
    pub licenses: Vec<License>,
    pub purl: String,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
    #[serde(default)]
    pub components: Vec<Component4>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License {
    pub expression: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalReference {
    pub url: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component4 {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub ref_field: String,
    pub depends_on: Vec<String>,
}
