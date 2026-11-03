package capability

// AssetType is a CTIS asset type name, as a producer writes it in
// assets[].type. The names follow CTIS 2.0. This module does not import the
// CTIS document package; a parity test in the platform checks this list
// against the CTIS schema.
type AssetType string

// CTIS 2.0 asset types.
const (
	AssetDomainName        AssetType = "domain_name"
	AssetIPAddress         AssetType = "ip_address"
	AssetIPRange           AssetType = "ip_range"
	AssetHost              AssetType = "host"
	AssetService           AssetType = "service"
	AssetWebOrigin         AssetType = "web_origin"
	AssetWebApplication    AssetType = "web_application"
	AssetAPI               AssetType = "api"
	AssetCertificate       AssetType = "certificate"
	AssetRepository        AssetType = "repository"
	AssetContainer         AssetType = "container"
	AssetContainerImage    AssetType = "container_image"
	AssetContainerRegistry AssetType = "container_registry"
	AssetPackage           AssetType = "package"
	AssetIdentity          AssetType = "identity"
	AssetCloudAccount      AssetType = "cloud_account"
	AssetCloudResource     AssetType = "cloud_resource"
	AssetKubernetesCluster AssetType = "kubernetes_cluster"
	AssetKubernetesNS      AssetType = "kubernetes_namespace"
	AssetKubernetesWL      AssetType = "kubernetes_workload"
	AssetDatabase          AssetType = "database"
	AssetStorage           AssetType = "storage"
	AssetServerless        AssetType = "serverless"
	AssetVPC               AssetType = "vpc"
	AssetSubnet            AssetType = "subnet"
	AssetLoadBalancer      AssetType = "load_balancer"
	AssetFirewall          AssetType = "firewall"
	AssetSaaSApplication   AssetType = "saas_application"
	AssetEndpointDevice    AssetType = "endpoint_device"
	AssetIoTDevice         AssetType = "iot_device"
	AssetOTDevice          AssetType = "ot_device"
	AssetNetworkDevice     AssetType = "network_device"
	AssetAutonomousSystem  AssetType = "autonomous_system"
	AssetAIModel           AssetType = "ai_model"
	AssetMobileApp         AssetType = "mobile_app"
	AssetSmartContract     AssetType = "smart_contract"
	AssetWallet            AssetType = "wallet"
	AssetToken             AssetType = "token"
	AssetNFTCollection     AssetType = "nft_collection"
	AssetDeFiProtocol      AssetType = "defi_protocol"
	AssetBlockchain        AssetType = "blockchain"
	AssetUnclassified      AssetType = "unclassified"
)

// AllAssetTypes returns every asset type name, in declaration order.
func AllAssetTypes() []AssetType {
	return []AssetType{
		AssetDomainName, AssetIPAddress, AssetIPRange, AssetHost, AssetService,
		AssetWebOrigin, AssetWebApplication, AssetAPI, AssetCertificate,
		AssetRepository, AssetContainer, AssetContainerImage, AssetContainerRegistry,
		AssetPackage, AssetIdentity, AssetCloudAccount, AssetCloudResource,
		AssetKubernetesCluster, AssetKubernetesNS, AssetKubernetesWL, AssetDatabase,
		AssetStorage, AssetServerless, AssetVPC, AssetSubnet, AssetLoadBalancer,
		AssetFirewall, AssetSaaSApplication, AssetEndpointDevice, AssetIoTDevice,
		AssetOTDevice, AssetNetworkDevice, AssetAutonomousSystem, AssetAIModel,
		AssetMobileApp, AssetSmartContract, AssetWallet, AssetToken,
		AssetNFTCollection, AssetDeFiProtocol, AssetBlockchain, AssetUnclassified,
	}
}
