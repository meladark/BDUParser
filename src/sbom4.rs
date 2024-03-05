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
    pub components: Option<Vec<Component>>,
    pub services: Option<Vec<Service>>,
    pub external_references: Option<Vec<ExternalReference>>,
    pub dependencies: Option<Vec<Dependencie>>,
    pub compositions: Option<Vec<Composition>>,
    pub vulnerabilities: Option<Vec<Vulnerabilitie>>,
    //TODO: Add signature
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub timestamp: Option<String>,
    pub tool: Option<Vec<Tool>>,
    pub authors: Option<Vec<Author>>,
    pub component: Option<Component>,
    pub manufacture: Option<Manufactore>,
    pub supplier: Option<Supplier>,
    //TODO: Add license
    pub properties: Option<Vec<Propertie>>,
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
    pub pedigree: Option<Pedigree>,
    pub external_references: Option<Vec<ExternalReference>>,
    pub components: Option<Vec<Component>>,
    pub evidence: Option<Evidence>,
    pub release_notes: Option<ReleaseNotes>,
    pub properties: Option<Vec<Propertie>>, //TODO: Add signature
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
    pub content_type: Option<String>,
    pub encoding: Option<String>,
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pedigree {
    pub ancestors: Option<Vec<Component>>,
    pub descendants: Option<Vec<Component>>,
    pub variants: Option<Vec<Component>>,
    pub commits: Option<Vec<Commit>>,
    pub patches: Option<Vec<Patch>>,
    pub notes: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Commit {
    pub uid: Option<String>,
    pub url: Option<String>,
    pub author: Option<Author>,
    pub committer: Option<Author>,
    pub message: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Patch {
    #[serde(rename = "type")]
    pub type_field: String, //TODO: add enum
    pub diff: Option<Diff>,
    pub resolves: Option<Vec<Resolv>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diff {
    pub text: Option<Text>,
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolv {
    #[serde(rename = "type")]
    pub type_field: String, //TODO: add enum
    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub source: Option<Source>,
    pub references: Option<Vec<String>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    //TODO Licenses
    pub copyright: Option<Vec<Copyright>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Copyright {
    pub text: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseNotes {
    #[serde(rename = "type")]
    pub type_field: String,
    pub title: Option<String>,
    pub featured_image: Option<String>,
    pub social_image: Option<String>,
    pub description: Option<String>,
    pub timestamp: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub resolves: Option<Vec<Resolv>>,
    pub notes: Option<Vec<Note>>,
    pub properties: Option<Vec<Propertie>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub locale: Option<String>,
    pub text: Text,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propertie {
    name: Option<String>,
    value: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manufactore {
    pub name: Option<String>,
    pub url: Option<String>,
    pub contact: Option<Vec<Author>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub provider: Option<Supplier>,
    pub group: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub endpoints: Option<Vec<String>>,
    pub authenticated: Option<bool>,
    #[serde(rename = "x-trust-boundary")]
    pub x_trust_boundary: Option<bool>,
    pub data: Option<Vec<Data>>,
    //TODO: add license
    pub external_references: Option<Vec<ExternalReference>>,
    pub services: Option<Vec<Service>>,
    pub release_notes: Option<ReleaseNotes>,
    pub properties: Option<Vec<Propertie>>,
    //TODO: add signature
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub flow: String, //TODO: add enum,
    pub classification: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependencie {
    #[serde(rename = "ref")]
    pub ref_field: String,
    pub depends_on: Option<Vec<String>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Composition {
    pub aggregate: String, //TODO: add enum
    pub assemblies: Option<Vec<String>>,
    pub dependencies: Option<Vec<String>>,
    //TODO: add signature
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerabilitie {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    pub id: Option<String>,
    pub source: Option<Source>,
    pub references: Option<Vec<Reference>>,
    pub ratings: Option<Vec<Rating>>,
    pub cwes: Option<Vec<i32>>,
    pub description: Option<String>,
    pub detail: Option<String>,
    pub recommendation: Option<String>,
    pub advisories: Option<Vec<Advisorie>>,
    pub created: Option<String>,
    pub published: Option<String>,
    pub updated: Option<String>,
    pub credits: Option<Credit>,
    pub tools: Option<Vec<Tool>>,
    pub analysis: Option<Analysis>,
    pub affects: Option<Vec<Affect>>,
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub id: String,
    pub source: Source,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rating {
    pub source: Option<Source>,
    pub score: Option<i32>,
    pub severity: Option<String>, //TODO: add enum
    pub method: Option<String>,   //TODO: add enum
    pub vector: Option<String>,
    pub justificatiom: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Advisorie {
    pub title: Option<String>,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credit {
    pub organizations: Option<Vec<Organization>>,
    pub individuals: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub name: Option<String>,
    pub url: Option<String>,
    pub contact: Option<Vec<Author>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub state: Option<String>,         //TODO: Add enum
    pub justification: Option<String>, //TODO: Add enum
    pub response: Option<String>,      //TODO: Add enum
    pub detail: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affect {
    #[serde(rename = "ref")]
    pub ref_field: String,
    //TODO: ADD Versions
}
