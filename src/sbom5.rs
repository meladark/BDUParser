use core::str;

//TODO: Add scheme 5
use crate::bdu::Version;
use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    /// Specifies the format of the BOM. This helps to identify the file as CycloneDX since BOMs do not have a filename convention nor does JSON schema support namespaces. This value MUST be "CycloneDX".
    pub bom_format: String,
    /// The version of the CycloneDX specification a BOM conforms to (starting at version 1.2).
    pub spec_version: String,
    /// Every BOM generated SHOULD have a unique serial number, even if the contents of the BOM have not changed over time. If specified, the serial number MUST conform to RFC-4122. Use of serial numbers are RECOMMENDED.
    /// Must match regular expression: `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
    pub serial_number: Option<String>,
    /// Whenever an existing BOM is modified, either manually or through automated processes, the version of the BOM SHOULD be incremented by 1. When a system is presented with multiple BOMs with identical serial numbers, the system SHOULD use the most recent version of the BOM. The default version is '1'.
    /// Value must be greater or equal to 1
    pub version: Option<i32>,
    /// Provides additional information about a BOM.
    pub metadata: Option<Metadata>,
    /// Compositions describe constituent parts (including components, services, and dependency relationships) and their completeness. The completeness of vulnerabilities expressed in a BOM may also be described.
    pub components: Option<Vec<Component>>,
    /// Vulnerabilities identified in components or services
    pub vulnerabilities: Option<Vec<Vulnerabilitie>>,
    /// Comments made by people, organizations, or tools about any object with a bom-ref, such as components, services, vulnerabilities, or the BOM itself. Unlike inventory information, annotations may contain opinion or commentary from various stakeholders. Annotations may be inline (with inventory) or externalized via BOM-Link, and may optionally be signed.
    pub annotations: Option<Vec<Annotation>>,
    /// Describes how a component or service was manufactured or deployed. This is achieved through the use of formulas, workflows, tasks, and steps, which declare the precise steps to reproduce along with the observed formulas describing the steps which transpired in the manufacturing process.
    pub formulation: Option<Vec<Formulation>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
    // TODO: signature
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// The date and time (timestamp) when the BOM was created.
    pub timestamp: Option<String>,
    // TODO: lifecycles
    pub tool: Option<Vec<Tool>>, // TODO: Необходимо удовлетворить то, что вариантов теперь может быть несколько
    /// The person(s) who created the BOM. Authors are common in BOMs created through manual processes. BOMs created through automated means may not have authors.
    pub authors: Option<Vec<Author>>,
    /// The component that the BOM describes.
    pub component: Option<Component>,
    /// The organization that manufactured the component that the BOM describes.
    pub manufacture: Option<Manufactore>,
    /// The organization that supplied the component that the BOM describes. The supplier may often be the manufacturer, but may also be a distributor or repackager.
    pub supplier: Option<Supplier>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// **Deprecated** The tool(s) used in the creation of the BOM.
pub struct Tool {
    /// The name of the vendor who created the tool
    pub vendor: Option<String>,
    /// The name of the tool
    pub name: Option<String>,
    /// The version of the tool
    pub version: Option<String>,
    /// The hashes of the tool (if applicable).
    pub hashes: Option<Vec<Hash>>,
    /// External references provide a way to document systems, sites, and information that may be relevant, but are not included with the BOM. They may also establish specific relationships within or external to the BOM.
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The hashes of the tool (if applicable).
pub struct Hash {
    /// Must be one of: "MD5" "SHA-1" "SHA-256" "SHA-384" "SHA-512" "SHA3-256" "SHA3-384" "SHA3-512" "BLAKE2b-256" "BLAKE2b-384" "BLAKE2b-512" "BLAKE3"
    pub alg: String,
    /// Must match regular expression: `^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$`
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// External references provide a way to document systems, sites, and information that may be relevant, but are not included with the BOM. They may also establish specific relationships within or external to the BOM.
pub struct ExternalReference {
    /// The URI (URL or URN) to the external reference.
    /// External references are URIs and therefore can accept any URL scheme including https (RFC-7230), mailto (RFC-2368), tel (RFC-3966), and dns (RFC-4501).
    /// External references may also include formally registered URNs such as CycloneDX BOM-Link to reference CycloneDX BOMs or any object within a BOM.
    /// BOM-Link transforms applicable external references into relationships that can be expressed in a BOM or across BOMs.
    /// Can Be One of Two:
    /// Just URL
    /// BOM-Link:
    /// - BOM-Link Documents - Descriptor for another BOM document. See https://cyclonedx.org/capabilities/bomlink/
    /// Must match regular expression: `^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*$`
    /// - BOM-Link Element - Descriptor for an element in a BOM document. See https://cyclonedx.org/capabilities/bomlink/
    /// Must match regular expression: ^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$
    pub url: String,
    /// An optional comment describing the external reference
    pub comment: Option<String>,
    /// Specifies the type of external reference.
    /// - vcs = Version Control System
    /// - issue-tracker = Issue or defect tracking system, or an Application Lifecycle Management (ALM) system
    /// - website = Website
    /// - advisories = Security advisories
    /// - bom = Bill of Materials (SBOM, OBOM, HBOM, SaaSBOM, etc)
    /// - mailing-list = Mailing list or discussion group
    /// - social = Social media account
    /// - chat = Real-time chat platform
    /// - documentation = Documentation, guides, or how-to instructions
    /// - support = Community or commercial support
    /// - distribution = Direct or repository download location
    /// - distribution-intake = The location where a component was published to. This is often the same as "distribution" but may also include specialized publishing processes that act as an intermediary
    /// - license = The URL to the license file. If a license URL has been defined in the license node, it should also be defined as an external reference for completeness
    /// - build-meta = Build-system specific meta file (i.e. pom.xml, package.json, .nuspec, etc)
    /// - build-system = URL to an automated build system
    /// - release-notes = URL to release notes
    /// - security-contact = Specifies a way to contact the maintainer, supplier, or provider in the event of a security incident. Common URIs include links to a disclosure procedure, a mailto (RFC-2368) that specifies an email address, a tel (RFC-3966) that specifies a phone number, or dns (RFC-4501) that specifies the records containing DNS Security TXT
    /// - model-card = A model card describes the intended uses of a machine learning model, potential limitations, biases, ethical considerations, training parameters, datasets used to train the model, performance metrics, and other relevant data useful for ML transparency
    /// - log = A record of events that occurred in a computer system or application, such as problems, errors, or information on current operations
    /// - configuration = Parameters or settings that may be used by other components or services
    /// - evidence = Information used to substantiate a claim
    /// - formulation = Describes how a component or service was manufactured or deployed
    /// - attestation = Human or machine-readable statements containing facts, evidence, or testimony
    /// - threat-model = An enumeration of identified weaknesses, threats, and countermeasures, dataflow diagram (DFD), attack tree, and other supporting documentation in human-readable or machine-readable format
    /// - adversary-model = The defined assumptions, goals, and capabilities of an adversary.
    /// - risk-assessment = Identifies and analyzes the potential of future events that may negatively impact individuals, assets, and/or the environment. Risk assessments may also include judgments on the tolerability of each risk.
    /// - vulnerability-assertion = A Vulnerability Disclosure Report (VDR) which asserts the known and previously unknown vulnerabilities that affect a component, service, or product including the analysis and findings describing the impact (or lack of impact) that the reported vulnerability has on a component, service, or product.
    /// - exploitability-statement = A Vulnerability Exploitability eXchange (VEX) which asserts the known vulnerabilities that do not affect a product, product family, or organization, and optionally the ones that do. The VEX should include the analysis and findings describing the impact (or lack of impact) that the reported vulnerability has on the product, product family, or organization.
    /// - pentest-report = Results from an authorized simulated cyberattack on a component or service, otherwise known as a penetration test
    /// - static-analysis-report = SARIF or proprietary machine or human-readable report for which static analysis has identified code quality, security, and other potential issues with the source code
    /// - dynamic-analysis-report = Dynamic analysis report that has identified issues such as vulnerabilities and misconfigurations
    /// - runtime-analysis-report = Report generated by analyzing the call stack of a running application
    /// - component-analysis-report = Report generated by Software Composition Analysis (SCA), container analysis, or other forms of component analysis
    /// - maturity-report = Report containing a formal assessment of an organization, business unit, or team against a maturity model
    /// - certification-report = Industry, regulatory, or other certification from an accredited (if applicable) certification body
    /// - quality-metrics = Report or system in which quality metrics can be obtained
    /// - codified-infrastructure = Code or configuration that defines and provisions virtualized infrastructure, commonly referred to as Infrastructure as Code (IaC)
    /// - poam = Plans of Action and Milestones (POAM) compliment an "attestation" external reference. POAM is defined by NIST as a "document that identifies tasks needing to be accomplished. It details resources required to accomplish the elements of the plan, any milestones in meeting the tasks and scheduled completion dates for the milestones".
    /// - other = Use this if no other types accurately describe the purpose of the external reference
    #[serde(rename = "type")]
    pub type_field: String,
    /// The hashes of the tool (if applicable).
    pub hashes: Option<Vec<Hash>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Author {
    /// An optional identifier which can be used to reference the object elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The name of a contact
    pub name: Option<String>,
    /// The email address of the contact.
    pub email: Option<String>,
    /// The phone number of the contact.
    pub phone: Option<String>,
    /// The timestamp in which the action occurred
    pub timestamp: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    /// Specifies the type of component. For software components, classify as application if no more specific appropriate classification is available or cannot be determined for the component. Types include:
    /// - application = A software application. Refer to https://en.wikipedia.org/wiki/Application_software for information about applications.
    /// - framework = A software framework. Refer to https://en.wikipedia.org/wiki/Software_framework for information on how frameworks vary slightly from libraries.
    /// - library = A software library. Refer to https://en.wikipedia.org/wiki/Library_(computing)
    /// for information about libraries. All third-party and open source reusable components will likely be a library. If the library also has key features of a framework, then it should be classified as a framework. If not, or is unknown, then specifying library is RECOMMENDED.
    /// - container = A packaging and/or runtime format, not specific to any particular technology, which isolates software inside the container from software outside of a container through virtualization technology. Refer to https://en.wikipedia.org/wiki/OS-level_virtualization
    /// - platform = A runtime environment which interprets or executes software. This may include runtimes such as those that execute bytecode or low-code/no-code application platforms.
    /// - operating-system = A software operating system without regard to deployment model (i.e. installed on physical hardware, virtual machine, image, etc) Refer to https://en.wikipedia.org/wiki/Operating_system
    /// - device = A hardware device such as a processor, or chip-set. A hardware device containing firmware SHOULD include a component for the physical hardware itself, and another component of type 'firmware' or 'operating-system' (whichever is relevant), describing information about the software running on the device.
    /// See also the list of known device properties.
    /// - device-driver = A special type of software that operates or controls a particular type of device. Refer to https://en.wikipedia.org/wiki/Device_driver
    /// - firmware = A special type of software that provides low-level control over a devices hardware. Refer to https://en.wikipedia.org/wiki/Firmware
    /// - file = A computer file. Refer to https://en.wikipedia.org/wiki/Computer_file for information about files.
    /// - machine-learning-model = A model based on training data that can make predictions or decisions without being explicitly programmed to do so.
    /// - data = A collection of discrete values that convey information.
    #[serde(rename = "type")]
    pub type_field: String,
    /// The optional mime-type of the component. When used on file components, the mime-type can provide additional context about the kind of file being represented such as an image, font, or executable. Some library or framework components may also have an associated mime-type.
    /// Must match regular expression: `^[-+a-z0-9.]+/[-+a-z0-9.]+$`
    #[serde(rename = "mime-type")]
    pub mime_type: Option<String>,
    /// An optional identifier which can be used to reference the component elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The organization that supplied the component. The supplier may often be the manufacturer, but may also be a distributor or repackager.
    pub supplier: Option<Supplier>,
    /// The person(s) or organization(s) that authored the component
    pub author: Option<String>,
    /// The person(s) or organization(s) that published the component
    pub publisher: Option<String>,
    /// The grouping name or identifier. This will often be a shortened, single name of the company or project that produced the component, or the source package or domain name. Whitespace and special characters should be avoided. Examples include: apache, org.apache.commons, and apache.org.
    pub group: Option<String>,
    /// The name of the component. This will often be a shortened, single name of the component. Examples: commons-lang3 and jquery
    pub name: String,
    /// The component version. The version should ideally comply with semantic versioning but is not enforced.
    pub version: Option<String>,
    /// Specifies a description for the component
    pub description: Option<String>,
    /// Specifies the scope of the component. If scope is not specified, 'required' scope SHOULD be assumed by the consumer of the BOM.
    /// Must be one of: "required" "optional" "excluded"
    /// Default: "required"
    pub scope: Option<String>, // TODO: add enum
    pub hashes: Option<Vec<Hash>>,
    /// A copyright notice informing users of the underlying claims to copyright ownership in a published work.
    pub copyright: Option<String>,
    /// Specifies a well-formed CPE name that conforms to the CPE 2.2 or 2.3 specification.
    /// See https://nvd.nist.gov/products/cpe
    pub cpe: Option<String>,
    /// Specifies the package-url (purl).
    /// The purl, if specified, MUST be valid and conform to the specification defined at: https://github.com/package-url/purl-spec
    pub purl: Option<String>,
    /// Specifies metadata and content for ISO-IEC 19770-2 Software Identification (SWID) Tags.
    pub swid: Option<Swid>,
    /// **Deprecated** - DO NOT USE. This will be removed in a future version.
    /// Use the pedigree element instead to supply information on exactly how the component was modified.
    /// A boolean value indicating if the component has been modified from the original.
    /// A value of true indicates the component is a derivative of the original.
    /// A value of false indicates the component has not been modified from the original.
    pub modified: Option<bool>, //Deprecated
    /// Component pedigree is a way to document complex supply chain scenarios where components are created, distributed, modified, redistributed, combined with other components, etc.
    /// Pedigree supports viewing this complex chain from the beginning, the end, or anywhere in the middle.
    /// It also provides a way to document variants where the exact relation may not be known.
    pub pedigree: Option<Pedigree>,
    /// External references provide a way to document systems, sites, and information that may be relevant, but are not included with the BOM. They may also establish specific relationships within or external to the BOM.
    pub external_references: Option<Vec<ExternalReference>>,
    /// A list of software and hardware components included in the parent component. This is not a dependency tree. It provides a way to specify a hierarchical representation of component assemblies, similar to system → subsystem → parts assembly in physical supply chains.
    pub components: Option<Vec<Component>>,
    /// Provides the ability to document evidence collected through various forms of extraction or analysis.
    pub evidence: Option<Evidence>,
    /// Specifies optional release notes.
    pub release_notes: Option<ReleaseNotes>,
    /// A model card describes the intended uses of a machine learning model and potential limitations, including biases and ethical considerations. Model cards typically contain the training parameters, which datasets were used to train the model, performance metrics, and other relevant data useful for ML transparency. This object SHOULD be specified for any component of type machine-learning-model and MUST NOT be specified for other component types.
    pub model_card: Option<ModelCard>,
    /// This object SHOULD be specified for any component of type data and MUST NOT be specified for other component types.
    pub data: Option<Vec<Data>>,
    // TODO: Add lic
    pub properties: Option<Vec<Propertie>>,
    //TODO: Add signature
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Supplier {
    /// An optional identifier which can be used to reference the component elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The name of the organization
    pub name: Option<String>,
    /// The URL of the organization. Multiple URLs are allowed.
    pub url: Option<Vec<String>>,
    /// A contact at the organization. Multiple contacts are allowed.
    pub contact: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Specifies metadata and content for ISO-IEC 19770-2 Software Identification (SWID) Tags.
pub struct Swid {
    /// Maps to the tagId of a SoftwareIdentity.
    pub tag_id: String,
    /// Maps to the name of a SoftwareIdentity.
    pub name: String,
    /// Maps to the version of a SoftwareIdentity.
    /// Default: "0.0"
    pub version: Option<String>,
    /// Maps to the tagVersion of a SoftwareIdentity.
    /// Default: 0
    pub tag_version: Option<i32>,
    /// Maps to the patch of a SoftwareIdentity.
    /// Default: false
    pub patch: Option<bool>,
    /// Specifies the metadata and content of the SWID tag.
    pub text: Option<Text>,
    /// The URL to the SWID file.
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Specifies the metadata and content of the SWID tag.
pub struct Text {
    /// Specifies the content type of the text. Defaults to text/plain if not specified.
    /// Default: "text/plain"
    pub content_type: Option<String>,
    /// Specifies the optional encoding the text is represented in.
    /// Must be one of: "base64"
    pub encoding: Option<String>,
    /// The attachment data.
    /// Proactive controls such as input validation and sanitization should be employed to prevent misuse of attachment text.
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Component pedigree is a way to document complex supply chain scenarios where components are created, distributed, modified, redistributed, combined with other components, etc.
/// Pedigree supports viewing this complex chain from the beginning, the end, or anywhere in the middle. It also provides a way to document variants where the exact relation may not be known.
pub struct Pedigree {
    /// Describes zero or more components in which a component is derived from. This is commonly used to describe forks from existing projects where the forked version contains a ancestor node containing the original component it was forked from. For example, Component A is the original component. Component B is the component being used and documented in the BOM. However, Component B contains a pedigree node with a single ancestor documenting Component A - the original component from which Component B is derived from.
    pub ancestors: Option<Vec<Component>>,
    /// Descendants are the exact opposite of ancestors. This provides a way to document all forks (and their forks) of an original or root component.
    pub descendants: Option<Vec<Component>>,
    /// Variants describe relations where the relationship between the components are not known. For example, if Component A contains nearly identical code to Component B. They are both related, but it is unclear if one is derived from the other, or if they share a common ancestor.
    pub variants: Option<Vec<Component>>,
    /// A list of zero or more commits which provide a trail describing how the component deviates from an ancestor, descendant, or variant.
    pub commits: Option<Vec<Commit>>,
    /// A list of zero or more patches describing how the component deviates from an ancestor, descendant, or variant. Patches may be complimentary to commits or may be used in place of commits.
    pub patches: Option<Vec<Patch>>,
    /// Notes, observations, and other non-structured commentary describing the components pedigree.
    pub notes: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A list of zero or more commits which provide a trail describing how the component deviates from an ancestor, descendant, or variant.
pub struct Commit {
    /// A unique identifier of the commit. This may be version control specific. For example, Subversion uses revision numbers whereas git uses commit hashes.
    pub uid: Option<String>,
    /// The URL to the commit. This URL will typically point to a commit in a version control system.
    pub url: Option<String>,
    /// The author who created the changes in the commit
    pub author: Option<Author>,
    /// The person who committed or pushed the commit
    pub committer: Option<Author>,
    /// The text description of the contents of the commit
    pub message: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A list of zero or more patches describing how the component deviates from an ancestor, descendant, or variant. Patches may be complimentary to commits or may be used in place of commits.
pub struct Patch {
    /// Specifies the purpose for the patch including the resolution of defects, security issues, or new behavior or functionality.
    /// - unofficial = A patch which is not developed by the creators or maintainers of the software being patched. Refer to https://en.wikipedia.org/wiki/Unofficial_patch
    /// - monkey = A patch which dynamically modifies runtime behavior. Refer to https://en.wikipedia.org/wiki/Monkey_patch
    /// - backport = A patch which takes code from a newer version of software and applies it to older versions of the same software. Refer to https://en.wikipedia.org/wiki/Backporting
    /// - cherry-pick = A patch created by selectively applying commits from other versions or branches of the same software.
    #[serde(rename = "type")]
    pub type_field: String, //TODO: add enum
    /// The patch file (or diff) that show changes. Refer to https://en.wikipedia.org/wiki/Diff
    pub diff: Option<Diff>,
    /// A collection of issues the patch resolves
    pub resolves: Option<Vec<Resolv>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The patch file (or diff) that show changes. Refer to https://en.wikipedia.org/wiki/Diff
pub struct Diff {
    /// Specifies the optional text of the diff
    pub text: Option<Text>,
    /// Specifies the URL to the diff
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// An individual issue that has been resolved.
pub struct Resolv {
    /// Specifies the type of issue Must be one of: "defect" "enhancement" "security"
    #[serde(rename = "type")]
    pub type_field: String, //TODO: add enum
    /// The identifier of the issue assigned by the source of the issue
    pub id: Option<String>,
    /// The name of the issue
    pub name: Option<String>,
    /// A description of the issue
    pub description: Option<String>,
    /// The source of the issue where it is documented
    pub source: Option<Source>,
    /// A collection of URL's for reference. Multiple URLs are allowed.
    pub references: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The source of the issue where it is documented
pub struct Source {
    /// The name of the source. For example 'National Vulnerability Database', 'NVD', and 'Apache'
    pub name: Option<String>,
    /// The url of the issue documentation as provided by the source
    pub url: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Provides the ability to document evidence collected through various forms of extraction or analysis.
pub struct Evidence {
    /// Evidence that substantiates the identity of a component.
    pub identity: Option<Identity>,
    /// Evidence of individual instances of a component spread across multiple locations.
    pub occurrences: Option<Vec<Occurrence>>,
    /// Evidence of the components use through the callstack.
    pub callstack: Option<Callstack>,
    //TODO Licenses
    pub copyright: Option<Vec<Copyright>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// The identity field of the component which the evidence describes. Must be one of: "group" "name" "version" "purl" "cpe" "swid" "hash"
    pub field: String,
    /// The overall confidence of the evidence from 0 - 1, where 1 is 100% confidence.
    /// Value must be greater or equal to 0 and lesser or equal to 1
    pub confidence: Option<i32>,
    /// The methods used to extract and/or analyze the evidence.
    pub methods: Option<Vec<Method>>,
    /// The object in the BOM identified by its bom-ref.
    /// This is often a component or service, but may be any object type supporting bom-refs.
    /// Tools used for analysis should already be defined in the BOM, either in the metadata/tools, components, or formulation.
    /// All items must be unique
    pub tools: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The methods used to extract and/or analyze the evidence.
pub struct Method {
    /// The technique used in this method of analysis. Must be one of: "source-code-analysis" "binary-analysis" "manifest-analysis" "ast-fingerprint" "hash-comparison" "instrumentation" "dynamic-analysis" "filename" "attestation" "other"
    pub technique: String,
    /// The confidence of the evidence from 0 - 1, where 1 is 100% confidence.
    /// Confidence is specific to the technique used.
    /// Each technique of analysis can have independent confidence.
    /// Value must be greater or equal to 0 and lesser or equal to 1
    pub confidence: i32,
    /// The value or contents of the evidence.
    pub value: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Evidence of individual instances of a component spread across multiple locations.
pub struct Occurrence {
    /// An optional identifier which can be used to reference the object elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The location or path to where the component was found.
    pub location: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Evidence of the components use through the callstack.
pub struct Callstack {
    pub frames: Option<Vec<Frame>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    /// A package organizes modules into namespaces, providing a unique namespace for each type it contains.
    pub package: Option<String>,
    /// A module or class that encloses functions/methods and other code.
    pub module: String,
    /// A block of code designed to perform a particular task.
    pub function: Option<String>,
    /// Optional arguments that are passed to the module or function.
    pub parameters: Option<Vec<String>>,
    /// The line number the code that is called resides on.
    pub line: Option<i32>,
    /// The column the code that is called resides.
    pub column: Option<i32>,
    /// The full path and filename of the module.
    pub full_filename: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Copyright {
    pub text: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseNotes {
    /// The software versioning type the release note describes.
    #[serde(rename = "type")]
    pub type_field: String,
    /// The title of the release.
    pub title: Option<String>,
    /// The URL to an image that may be prominently displayed with the release note.
    pub featured_image: Option<String>,
    /// The URL to an image that may be used in messaging on social media platforms.
    pub social_image: Option<String>,
    /// A short description of the release.
    pub description: Option<String>,
    /// The date and time (timestamp) when the release note was created.
    pub timestamp: Option<String>,
    /// One or more alternate names the release may be referred to. This may include unofficial terms used by development and marketing teams (e.g. code names).
    pub aliases: Option<Vec<String>>,
    /// One or more tags that may aid in search or retrieval of the release note.
    pub tags: Option<Vec<String>>,
    /// A collection of issues that have been resolved.
    pub resolves: Option<Vec<Resolv>>,
    /// Zero or more release notes containing the locale and content. Multiple note objects may be specified to support release notes in a wide variety of languages.
    pub notes: Option<Vec<Note>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A note containing the locale and content.
pub struct Note {
    /// The ISO-639 (or higher) language code and optional ISO-3166 (or higher) country code. Examples include: "en", "en-US", "fr" and "fr-CA" Must match regular expression: `^([a-z]{2})(-[A-Z]{2})?$`
    pub locale: Option<String>,
    /// Specifies the full content of the release note.
    pub text: Text,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
pub struct Propertie {
    /// The name of the property. Duplicate names are allowed, each potentially having a different value.
    name: Option<String>,
    /// The value of the property.
    value: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A model card describes the intended uses of a machine learning model and potential limitations, including biases and ethical considerations. Model cards typically contain the training parameters, which datasets were used to train the model, performance metrics, and other relevant data useful for ML transparency. This object SHOULD be specified for any component of type machine-learning-model and MUST NOT be specified for other component types.
pub struct ModelCard {
    /// An optional identifier which can be used to reference the model card elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// Hyper-parameters for construction of the model.
    pub model_parameters: Option<ModelParameters>,
    /// quantitative_analysis
    pub quantitative_analysis: Option<QuantitativeAnalysis>,
    /// What considerations should be taken into account regarding the model's construction, training, and application?
    pub considerations: Option<Considerations>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Hyper-parameters for construction of the model.
pub struct ModelParameters {
    /// The overall approach to learning used by the model for problem solving.
    pub approach: Option<Approach>,
    /// Directly influences the input and/or output. Examples include classification, regression, clustering, etc.
    pub task: Option<String>,
    /// The model architecture family such as transformer network, convolutional neural network, residual neural network, LSTM neural network, etc.
    pub archirecture_family: Option<String>,
    /// The specific architecture of the model such as GPT-1, ResNet-50, YOLOv3, etc.
    pub model_architecture: Option<String>,
    // TODO: datasets
    /// The input format(s) of the model
    pub inputs: Option<Vec<Input>>,
    /// The output format(s) from the model
    pub outputs: Option<Vec<Output>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The overall approach to learning used by the model for problem solving.
pub struct Approach {
    /// Learning types describing the learning problem or hybrid learning problem.
    /// Must be one of: "supervised" "unsupervised" "reinforcement-learning" "semi-supervised" "self-supervised"
    #[serde(rename = "type")]
    pub type_field: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    /// The data format for input/output to the model. Example formats include string, image, time-series
    pub format: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    /// The data format for input/output to the model. Example formats include string, image, time-series
    pub format: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A quantitative analysis of the model
pub struct QuantitativeAnalysis {
    /// The model performance metrics being reported. Examples may include accuracy, F1 score, precision, top-3 error rates, MSC, etc.
    pub performance_metrics: Option<Vec<PerformanceMetric>>,
    /// A collection of graphics that represent various measurements.
    pub graphics: Option<Graphic>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The model performance metrics being reported. Examples may include accuracy, F1 score, precision, top-3 error rates, MSC, etc.
pub struct PerformanceMetric {
    /// The type of performance metric.
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    /// The value of the performance metric.
    pub value: Option<String>,
    /// The name of the slice this metric was computed on. By default, assume this metric is not sliced.
    pub slice: Option<String>,
    /// The confidence interval of the metric.
    pub confidence_interval: Option<ConfidenceInterval>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The confidence interval of the metric.
pub struct ConfidenceInterval {
    /// The lower bound of the confidence interval.
    pub lower_bound: Option<String>,
    /// The upper bound of the confidence interval.
    pub upper_bound: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A collection of graphics that represent various measurements.
pub struct Graphic {
    /// A description of this collection of graphics.
    pub description: Option<String>,
    /// A collection of graphics.
    pub collection: Option<Collection>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A collection of graphics.
pub struct Collection {
    /// The name of the graphic.
    pub name: Option<String>,
    /// The graphic (vector or raster). Base64 encoding MUST be specified for binary images.
    pub image: Option<Image>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The graphic (vector or raster). Base64 encoding MUST be specified for binary images.
pub struct Image {
    /// Specifies the content type of the text. Defaults to text/plain if not specified.
    pub content_type: Option<String>,
    /// Specifies the optional encoding the text is represented in.
    /// Must be one of:
    /// "base64"
    pub encoding: Option<String>,
    /// The attachment data. Proactive controls such as input validation and sanitization should be employed to prevent misuse of attachment text.
    pub content: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// What considerations should be taken into account regarding the model's construction, training, and application?
pub struct Considerations {
    /// Who are the intended users of the model?
    pub users: Option<Vec<String>>,
    /// What are the intended use cases of the model?
    pub use_cases: Option<Vec<String>>,
    /// What are the known technical limitations of the model? E.g. What kind(s) of data should the model be expected not to perform well on? What are the factors that might degrade model performance?
    pub technical_limitations: Option<Vec<String>>,
    /// What are the known tradeoffs in accuracy/performance of the model?
    pub performance_tradeoffs: Option<Vec<String>>,
    /// What are the ethical (or environmental) risks involved in the application of this model?
    pub ethical_considerations: Option<Vec<Ethical>>,
    pub fairness_assessments: Option<Vec<Fairness>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// What are the ethical (or environmental) risks involved in the application of this model?
pub struct Ethical {
    /// The name of the risk.
    pub name: Option<String>,
    /// Strategy used to address this risk.
    pub mitigation_strategy: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Information about the benefits and harms of the model to an identified at risk group.
pub struct Fairness {
    /// The groups or individuals at risk of being systematically disadvantaged by the model.
    pub group_at_risk: Option<String>,
    /// Expected benefits to the identified groups.
    pub benefits: Option<String>,
    /// Expected harms to the identified groups.
    pub harms: Option<String>,
    /// With respect to the benefits and harms outlined, please describe any mitigation strategy implemented.
    pub mitigation_strategy: Option<String>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// This object SHOULD be specified for any component of type data and MUST NOT be specified for other component types.
pub struct Data {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The general theme or subject matter of the data being specified.
    /// - source-code = Any type of code, code snippet, or data-as-code.
    /// - configuration = Parameters or settings that may be used by other components.
    /// - dataset = A collection of data.
    /// - definition = Data that can be used to create new instances of what the definition defines.
    /// - other = Any other type of data that does not fit into existing definitions.
    #[serde(rename = "type")]
    pub type_field: String,
    /// The name of the dataset.
    pub name: Option<String>,
    /// The contents or references to the contents of the data being described.
    pub contents: Option<Content>,
    /// Data classification tags data according to its type, sensitivity, and value if altered, stolen, or destroyed.
    pub classification: Option<String>,
    /// A description of any sensitive data in a dataset.
    pub sensitive_data: Option<Vec<String>>,
    /// A collection of graphics that represent various measurements.
    pub graphics: Option<Graphic>,
    /// A description of the dataset. Can describe size of dataset, whether it's used for source code, training, testing, or validation, etc.
    pub description: Option<String>,
    pub governance: Option<Governance>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The contents or references to the contents of the data being described.
pub struct Content {
    /// An optional way to include textual or encoded data.
    pub attachment: Option<Attachment>,
    /// The URL to where the data can be retrieved.
    pub url: Option<String>,
    /// Provides the ability to document name-value parameters used for configuration.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// An optional way to include textual or encoded data.
pub struct Attachment {
    /// Specifies the content type of the text. Defaults to text/plain if not specified.
    pub content_type: Option<String>,
    /// Specifies the optional encoding the text is represented in.
    /// Must be one of: "base64"
    pub encoding: Option<String>,
    /// The attachment data. Proactive controls such as input validation and sanitization should be employed to prevent misuse of attachment text.
    pub content: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Governance {
    /// Data custodians are responsible for the safe custody, transport, and storage of data.
    pub custodians: Option<Vec<Custodian>>,
    // TODO: stewards
    // TODO: owners
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Data custodians are responsible for the safe custody, transport, and storage of data.
pub struct Custodian {
    pub organization: Option<Organization>,
    pub contact: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    /// An optional identifier which can be used to reference the object elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The name of the organization
    pub name: Option<String>,
    /// The URL of the organization. Multiple URLs are allowed.
    pub url: Option<Vec<String>>,
    /// A contact at the organization. Multiple contacts are allowed.
    pub contact: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The organization that manufactured the component that the BOM describes.
pub struct Manufactore {
    /// An optional identifier which can be used to reference the object elsewhere in the BOM.
    /// Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    /// The name of the organization
    pub name: Option<String>,
    /// The URL of the organization. Multiple URLs are allowed.
    pub url: Option<String>,
    /// A contact at the organization. Multiple contacts are allowed.
    pub contact: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Defines a weakness in a component or service that could be exploited or triggered by a threat source.
pub struct Vulnerabilitie {
    /// An optional identifier which can be used to reference the vulnerability elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.
    /// Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The identifier that uniquely identifies the vulnerability.
    pub id: Option<String>,
    /// The source that published the vulnerability.
    pub source: Option<Source>,
    /// Zero or more pointers to vulnerabilities that are the equivalent of the vulnerability specified. Often times, the same vulnerability may exist in multiple sources of vulnerability intelligence, but have different identifiers. References provide a way to correlate vulnerabilities across multiple sources of vulnerability intelligence.
    pub references: Option<Vec<Reference>>,
    /// Defines the severity or risk ratings of a vulnerability.
    pub ratings: Option<Vec<Rating>>,
    /// List of Common Weaknesses Enumerations (CWEs) codes that describes this vulnerability. For example 399 (of https://cwe.mitre.org/data/definitions/399.html)
    pub cwes: Option<Vec<i32>>,
    /// A description of the vulnerability as provided by the source.
    pub description: Option<String>,
    /// If available, an in-depth description of the vulnerability as provided by the source organization. Details often include information useful in understanding root cause.
    pub detail: Option<String>,
    /// Recommendations of how the vulnerability can be remediated or mitigated.
    pub recommendation: Option<String>,
    /// A bypass, usually temporary, of the vulnerability that reduces its likelihood and/or impact. Workarounds often involve changes to configuration or deployments.
    pub workaround: Option<String>,
    /// Evidence used to reproduce the vulnerability.
    pub proof_of_concept: Option<ProofOfConcept>,
    /// Published advisories of the vulnerability if provided.
    pub advisories: Option<Vec<Advisorie>>,
    /// The date and time (timestamp) when the vulnerability record was created in the vulnerability database.
    pub created: Option<String>,
    /// The date and time (timestamp) when the vulnerability record was first published.
    pub published: Option<String>,
    /// The date and time (timestamp) when the vulnerability record was last updated.
    pub updated: Option<String>,
    /// The date and time (timestamp) when the vulnerability record was rejected (if applicable).
    pub rejected: Option<String>,
    /// Individuals or organizations credited with the discovery of the vulnerability.
    pub credits: Option<Credit>,
    ///
    pub tools: Option<Vec<Tool>>,
    /// An assessment of the impact and exploitability of the vulnerability.
    pub analysis: Option<Analysis>,
    /// The components or services that are affected by the vulnerability.
    pub affects: Option<Vec<Affect>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Zero or more pointers to vulnerabilities that are the equivalent of the vulnerability specified. Often times, the same vulnerability may exist in multiple sources of vulnerability intelligence, but have different identifiers. References provide a way to correlate vulnerabilities across multiple sources of vulnerability intelligence.
pub struct Reference {
    /// An identifier that uniquely identifies the vulnerability.
    pub id: String,
    /// The source that published the vulnerability.
    pub source: Source,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Defines the severity or risk ratings of a vulnerability.
pub struct Rating {
    /// The source that calculated the severity or risk rating of the vulnerability.
    pub source: Option<Source>,
    /// The numerical score of the rating.
    pub score: Option<f32>,
    /// Textual representation of the severity that corresponds to the numerical score of the rating.
    /// Must be one of: "critical" "high" "medium" "low" "info" "none" "unknown"
    pub severity: Option<String>, //TODO: add enum
    /// Specifies the severity or risk scoring methodology or standard used.
    /// - CVSSv2 - Common Vulnerability Scoring System v2
    /// - CVSSv3 - Common Vulnerability Scoring System v3
    /// - CVSSv31 - Common Vulnerability Scoring System v3.1
    /// - CVSSv4 - Common Vulnerability Scoring System v4
    /// - OWASP - OWASP Risk Rating Methodology
    /// - SSVC - Stakeholder Specific Vulnerability Categorization (all versions)
    pub method: Option<String>, //TODO: add enum
    /// Textual representation of the metric values used to score the vulnerability
    pub vector: Option<String>,
    /// An optional reason for rating the vulnerability as it was
    pub justificatiom: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Evidence used to reproduce the vulnerability.
pub struct ProofOfConcept {
    /// Precise steps to reproduce the vulnerability.
    pub reproduction_steps: Option<String>,
    /// A description of the environment in which reproduction was possible.
    pub environment: Option<String>,
    /// Supporting material that helps in reproducing or understanding how reproduction is possible. This may include screenshots, payloads, and PoC exploit code.
    pub supporting_material: Option<Vec<SupportingMaterial>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Supporting material that helps in reproducing or understanding how reproduction is possible. This may include screenshots, payloads, and PoC exploit code.
pub struct SupportingMaterial {
    /// Specifies the content type of the text. Defaults to text/plain if not specified.
    pub content_type: Option<String>,
    /// Specifies the optional encoding the text is represented in.
    /// Must be one of: "base64"
    pub encoding: Option<String>,
    /// The attachment data. Proactive controls such as input validation and sanitization should be employed to prevent misuse of attachment text.
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Title and location where advisory information can be obtained. An advisory is a notification of a threat to a component, service, or system.
pub struct Advisorie {
    /// An optional name of the advisory.
    pub title: Option<String>,
    /// Location where the advisory can be obtained.
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Individuals or organizations credited with the discovery of the vulnerability.
pub struct Credit {
    /// The organizations credited with vulnerability discovery.
    pub organizations: Option<Vec<Organization>>,
    /// The individuals, not associated with organizations, that are credited with vulnerability discovery.
    pub individuals: Option<Vec<Author>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// An assessment of the impact and exploitability of the vulnerability.
pub struct Analysis {
    /// Declares the current state of an occurrence of a vulnerability, after automated or manual analysis.
    /// - resolved = the vulnerability has been remediated.
    /// - resolved_with_pedigree = the vulnerability has been remediated and evidence of the changes are provided in the affected components pedigree containing verifiable commit history and/or diff(s).
    /// - exploitable = the vulnerability may be directly or indirectly exploitable.
    /// - in_triage = the vulnerability is being investigated.
    /// - false_positive = the vulnerability is not specific to the component or service and was falsely identified or associated.
    /// - not_affected = the component or service is not affected by the vulnerability. Justification should be specified for all not_affected cases.
    pub state: Option<String>, //TODO: Add enum
    /// The rationale of why the impact analysis state was asserted.
    /// - code_not_present = the code has been removed or tree-shaked.
    /// - code_not_reachable = the vulnerable code is not invoked at runtime.
    /// - requires_configuration = exploitability requires a configurable option to be set/unset.
    /// - requires_dependency = exploitability requires a dependency that is not present.
    /// - requires_environment = exploitability requires a certain environment which is not present.
    /// - protected_by_compiler = exploitability requires a compiler flag to be set/unset.
    /// - protected_at_runtime = exploits are prevented at runtime.
    /// - protected_at_perimeter = attacks are blocked at physical, logical, or network perimeter.
    /// - protected_by_mitigating_control = preventative measures have been implemented that reduce the likelihood and/or impact of the vulnerability.
    pub justification: Option<String>, //TODO: Add enum
    /// A response to the vulnerability by the manufacturer, supplier, or project responsible for the affected component or service. More than one response is allowed. Responses are strongly encouraged for vulnerabilities where the analysis state is exploitable.
    pub response: Option<Vec<String>>, //TODO: Add enum
    /// Detailed description of the impact including methods used during assessment. If a vulnerability is not exploitable, this field should include specific details on why the component or service is not impacted by this vulnerability.
    pub detail: Option<String>,
    /// The date and time (timestamp) when the analysis was first issued.
    pub first_issued: Option<String>,
    /// The date and time (timestamp) when the analysis was last updated.
    pub last_updated: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affect {
    /// References a component or service by the objects bom-ref
    /// Descriptor for an element identified by the attribute 'bom-ref' in the same BOM document.
    /// In contrast to bomLinkElementType.
    /// Must be at least 1 characters long
    ///
    /// Descriptor for an element in a BOM document. See https://cyclonedx.org/capabilities/bomlink/
    /// Must match regular expression: `^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$`
    #[serde(rename = "ref")]
    pub ref_field: String,
    /// Zero or more individual versions or range of versions.
    pub versions: Option<Vec<Version>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Comments made by people, organizations, or tools about any object with a bom-ref, such as components, services, vulnerabilities, or the BOM itself. Unlike inventory information, annotations may contain opinion or commentary from various stakeholders. Annotations may be inline (with inventory) or externalized via BOM-Link, and may optionally be signed.
pub struct Annotation {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The object in the BOM identified by its bom-ref.
    /// This is often a component or service, but may be any object type supporting bom-refs.
    /// All items must be unique
    /// - Ref - Descriptor for an element identified by the attribute 'bom-ref' in the same BOM document In contrast to bomLinkElementType. Must be at least 1 characters long
    /// - BOM-Link Element - Descriptor for an element in a BOM document. See https://cyclonedx.org/capabilities/bomlink/ Must match regular expression: `^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$`
    pub subjects: Vec<String>,
    /// The organization, person, component, or service which created the textual content of the annotation.
    pub annotator: Annotator,
    /// The date and time (timestamp) when the annotation was created.
    pub timestamp: String,
    /// The textual content of the annotation.
    pub text: String,
    //TODO Signature
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The organization, person, component, or service which created the textual content of the annotation.
pub struct Annotator {
    /// The organization that created the annotation
    pub organization: Option<Organization>,
    /// The person that created the annotation
    pub individual: Option<Author>,
    /// The tool or component that created the annotation
    pub component: Option<Component>,
    /// The service that created the annotation
    pub service: Option<Service>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The service that created the annotation
pub struct Service {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// The organization that provides the service.
    pub provider: Option<Organization>,
    /// The grouping name, namespace, or identifier. This will often be a shortened, single name of the company or project that produced the service or domain name. Whitespace and special characters should be avoided.
    pub group: Option<String>,
    // The name of the service. This will often be a shortened, single name of the service.
    pub name: String,
    /// The service version.
    pub version: Option<String>,
    /// Specifies a description for the service
    pub description: Option<String>,
    /// The endpoint URIs of the service. Multiple endpoints are allowed.
    pub endpoints: Option<Vec<String>>,
    /// A boolean value indicating if the service requires authentication. A value of true indicates the service requires authentication prior to use. A value of false indicates the service does not require authentication.
    pub authenticated: Option<bool>,
    /// A boolean value indicating if use of the service crosses a trust zone or boundary. A value of true indicates that by using the service, a trust boundary is crossed. A value of false indicates that by using the service, a trust boundary is not crossed.
    #[serde(rename = "x-trust-boundary")]
    pub x_trust_boundary: Option<bool>,
    /// The name of the trust zone the service resides in.
    pub trust_zone: Option<String>,
    /// Specifies information about the data including the directional flow of data and the data classification.
    pub data: Option<Vec<DataService>>,
    // TODO: Licenses
    /// External references provide a way to document systems, sites, and information that may be relevant, but are not included with the BOM. They may also establish specific relationships within or external to the BOM.
    pub external_references: Option<Vec<ExternalReference>>,
    /// A list of services included or deployed behind the parent service. This is not a dependency tree. It provides a way to specify a hierarchical representation of service assemblies.
    pub services: Option<Vec<Service>>,
    /// Specifies optional release notes.
    pub release_notes: Option<ReleaseNotes>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
    // TODO: Signature
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataService {
    /// Specifies the flow direction of the data. Direction is relative to the service. Inbound flow states that data enters the service. Outbound flow states that data leaves the service. Bi-directional states that data flows both ways, and unknown states that the direction is not known.
    /// Must be one of: "inbound" "outbound" "bi-directional" "unknown"
    pub flow: String,
    /// Data classification tags data according to its type, sensitivity, and value if altered, stolen, or destroyed.
    pub classification: String,
    /// Name for the defined data
    pub name: Option<String>,
    /// Short description of the data content and usage
    pub description: Option<String>,
    pub governance: Option<Governance>,
    /// The URI, URL, or BOM-Link of the components or services the data came in from URL or BOM-Link Element
    pub source: Option<Vec<String>>,
    /// The URI, URL, or BOM-Link of the components or services the data came in from URL or BOM-Link Element
    pub destination: Option<Vec<String>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Describes workflows and resources that captures rules and other aspects of how the associated BOM component or service was formed.
pub struct Formulation {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,
    /// Transient components that are used in tasks that constitute one or more of this formula's workflows
    pub components: Option<Vec<Component>>,
    /// Transient services that are used in tasks that constitute one or more of this formula's workflows
    pub services: Option<Vec<Service>>,
    /// List of workflows that can be declared to accomplish specific orchestrated goals and independently triggered.
    pub workflows: Option<Vec<Workflow>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// List of workflows that can be declared to accomplish specific orchestrated goals and independently triggered.
pub struct Workflow {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The unique identifier for the resource instance within its deployment context.
    pub uid: String,
    /// The name of the resource instance.
    pub name: Option<String>,
    /// A description of the resource instance.
    pub description: Option<String>,
    /// References to component or service resources that are used to realize the resource instance.
    pub resource_references: Option<Vec<ResourceReferences>>,
    /// The tasks that comprise the workflow.
    pub tasks: Option<Vec<Task>>,
    /// The graph of dependencies between tasks within the workflow.
    pub task_dependencies: Option<Vec<RuntimeTopology>>,
    /// Indicates the types of activities performed by the set of workflow tasks.
    /// Each item of this array must be:
    /// Type: enum (of string)
    /// Must be one of: "copy" "clone" "lint" "scan" "merge" "build" "test" "deliver" "deploy" "release" "clean" "other"
    pub task_types: Vec<String>,
    /// The trigger that initiated the task.
    pub trigger: Option<Trigger>,
    /// The sequence of steps for the task.
    pub steps: Option<Vec<Step>>,
    /// Represents resources and data brought into a task at runtime by executor or task commands
    pub inputs: Option<Vec<Input>>,
    /// Represents resources and data output from a task at runtime by executor or task commands
    pub outputs: Option<Vec<Output>>,
    /// The date and time (timestamp) when the task started.
    pub time_start: Option<String>,
    /// The date and time (timestamp) when the task ended.
    pub time_end: Option<String>,
    /// A set of named filesystem or data resource shareable by workflow tasks.
    pub workspaces: Option<Vec<Workspace>>,
    /// A graph of the component runtime topology for workflow's instance.
    pub runtime_topology: Option<Vec<RuntimeTopology>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// References to component or service resources that are used to realize the resource instance.
pub struct ResourceReferences {
    /// References an object by its bom-ref attribute
    #[serde(rename = "ref")]
    pub ref_field: Option<String>,
    /// Reference to an externally accessible resource.
    pub external_reference: Option<ExternalReference>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Describes the inputs, sequence of steps and resources used to accomplish a task and its output.
pub struct Task {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The unique identifier for the resource instance within its deployment context.
    pub uid: String,
    /// The name of the resource instance.
    pub name: Option<String>,
    /// A description of the resource instance.
    pub description: Option<String>,
    /// References to component or service resources that are used to realize the resource instance.
    pub resource_references: Option<Vec<ResourceReferences>>,
    /// Indicates the types of activities performed by the set of workflow tasks.
    /// Each item of this array must be:
    /// Type: enum (of string)
    /// Must be one of: "copy" "clone" "lint" "scan" "merge" "build" "test" "deliver" "deploy" "release" "clean" "other"
    pub task_types: Vec<String>,
    /// The trigger that initiated the task.
    pub trigger: Option<Trigger>,
    /// The sequence of steps for the task.
    pub steps: Option<Vec<Step>>,
    /// Represents resources and data brought into a task at runtime by executor or task commands
    pub inputs: Option<Vec<Input>>,
    /// Represents resources and data output from a task at runtime by executor or task commands
    pub outputs: Option<Vec<Output>>,
    /// The date and time (timestamp) when the task started.
    pub time_start: Option<String>,
    /// The date and time (timestamp) when the task ended.
    pub time_end: Option<String>,
    /// A set of named filesystem or data resource shareable by workflow tasks.
    pub workspaces: Option<Vec<Workspace>>,
    /// A graph of the component runtime topology for task's instance.
    pub runtime_topology: Option<Vec<RuntimeTopology>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The trigger that initiated the task.
pub struct Trigger {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The unique identifier for the resource instance within its deployment context.
    pub uid: String,
    /// The name of the resource instance.
    pub name: Option<String>,
    /// A description of the resource instance.
    pub description: Option<String>,
    /// References to component or service resources that are used to realize the resource instance.
    pub resource_references: Option<Vec<ResourceReferences>>,
    /// The source type of event which caused the trigger to fire.
    /// Must be one of: "manual" "api" "webhook" "scheduled"
    #[serde(rename = "type")]
    pub type_field: String,
    /// The event data that caused the associated trigger to activate.
    pub event: Option<Event>,
    /// All items must be unique
    pub conditions: Option<Vec<Condition>>,
    /// The date and time (timestamp) when the trigger was activated.
    pub time_activated: Option<String>,
    /// Represents resources and data brought into a task at runtime by executor or task commands
    pub inputs: Option<Vec<Input>>,
    /// Represents resources and data output from a task at runtime by executor or task commands
    pub outputs: Option<Vec<Output>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// The unique identifier of the event.
    pub uid: Option<String>,
    /// A description of the event.
    pub description: Option<String>,
    /// The date and time (timestamp) when the event was received.
    pub time_received: Option<String>,
    /// Encoding of the raw event data.
    pub data: Option<DataEvent>,
    /// References the component or service that was the source of the event
    pub source: Option<Source>,
    /// References the component or service that was the target of the event
    pub target: Option<Target>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Encoding of the raw event data.
pub struct DataEvent {
    /// Specifies the content type of the text. Defaults to text/plain if not specified.
    pub content_type: Option<String>,
    ///Specifies the optional encoding the text is represented in.
    /// Must be one of: "base64"
    pub encoding: Option<String>,
    /// The attachment data. Proactive controls such as input validation and sanitization should be employed to prevent misuse of attachment text.
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A condition that was used to determine a trigger should be activated.
pub struct Condition {
    /// Describes the set of conditions which cause the trigger to activate.
    pub description: Option<String>,
    /// The logical expression that was evaluated that determined the trigger should be fired.
    pub expression: Option<String>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Propertie>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// References the component or service that was the target of the event
pub struct Target {
    /// References an object by its bom-ref attribute
    #[serde(rename = "ref")]
    pub ref_field: Option<String>,
    /// Reference to an externally accessible resource.
    pub external_reference: Option<ExternalReference>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Executes specific commands or tools in order to accomplish its owning task as part of a sequence.
pub struct Step {
    /// A name for the step.
    pub name: Option<String>,
    /// A description of the step.
    pub description: Option<String>,
    /// Ordered list of commands or directives for the step
    pub commands: Option<Vec<Command>>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Ordered list of commands or directives for the step
pub struct Command {
    /// A text representation of the executed command.
    pub executed: Option<String>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    /// An optional identifier which can be used to reference the dataset elsewhere in the BOM. Every bom-ref MUST be unique within the BOM. Must be at least 1 characters long
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The unique identifier for the resource instance within its deployment context.
    pub uid: String,
    /// The name of the resource instance.
    pub name: Option<String>,
    /// The names for the workspace as referenced by other workflow tasks. Effectively, a name mapping so other tasks can use their own local name in their steps
    pub aliases: Option<Vec<String>>,
    /// A description of the resource instance.
    pub description: Option<String>,
    /// References to component or service resources that are used to realize the resource instance.
    pub resource_references: Option<Vec<ResourceReferences>>,
    /// Describes the read-write access control for the workspace relative to the owning resource instance.
    /// Must be one of: "read-only" "read-write" "read-write-once" "write-once" "write-only"
    pub access_mode: Option<String>,
    /// A path to a location on disk where the workspace will be available to the associated task's steps.
    pub mount_path: Option<String>,
    /// The name of a domain-specific data type the workspace represents.
    pub managed_data_type: Option<String>,
    /// Identifies the reference to the request for a specific volume type and parameters
    pub volume_reques: Option<String>,
    /// Information about the actual volume instance allocated to the workspace.
    pub volume: Option<Volume>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// The unique identifier for the volume instance within its deployment context.
    pub uid: Option<String>,
    /// The name of the volume instance
    pub name: Option<String>,
    /// The mode for the volume instance.
    /// Must be one of: "filesystem" "block"
    pub mode: Option<String>,
    /// The underlying path created from the actual volume.
    pub path: Option<String>,
    /// The allocated size of the volume accessible to the associated workspace. This should include the scalar size as well as IEC standard unit in either decimal or binary form.
    pub size_allocated: Option<String>,
    /// Indicates if the volume persists beyond the life of the resource it is associated with.
    pub persistent: Option<bool>,
    /// Indicates if the volume is remotely (i.e., network) attached.
    pub remote: Option<bool>,
    /// Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the CycloneDX Property Taxonomy. Formal registration is OPTIONAL.
    pub properties: Option<Vec<Propertie>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A graph of the component runtime topology for task's instance.
pub struct RuntimeTopology {
    /// References an object by its bom-ref attribute
    #[serde(rename = "ref")]
    pub ref_field: String,
    /// The bom-ref identifiers of the components or services that are dependencies of this dependency object.
    /// All items must be unique Each item of this array must be:
    /// Descriptor for an element identified by the attribute 'bom-ref' in the same BOM document.
    /// In contrast to bomLinkElementType. Must be at least 1 characters long
    pub depends_on: Option<Vec<String>>,
}
