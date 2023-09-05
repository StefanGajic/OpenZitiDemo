package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	svc "example.com/openzitidemo/service"

	"example.com/openzitidemo/common"
	"github.com/openziti/edge-api/rest_management_api_client"
	"github.com/openziti/edge-api/rest_management_api_client/identity"
	"github.com/openziti/edge-api/rest_management_api_client/service"
	"github.com/openziti/edge-api/rest_management_api_client/service_policy"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
)

const (
	defaultProvider = "auth0"
)

var client *rest_management_api_client.ZitiEdgeManagement
var jwtToken string

func main() {
	var err error
	zitiAdminUsername := os.Getenv("OPENZITI_USER")
	zitiAdminPassword := os.Getenv("OPENZITI_PWD")
	ctrlAddress := os.Getenv("OPENZITI_CTRL")
	erName := os.Getenv("ZITI_ROUTER_NAME")
	if erName == "" {
		erName = "ziti-edge-router"
	}

	// Authenticate with the controller
	caCerts, err := rest_util.GetControllerWellKnownCas(ctrlAddress) // "https://stefan-L15:1280"
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}
	client, err = rest_util.NewEdgeManagementClientWithUpdb(zitiAdminUsername, zitiAdminPassword, ctrlAddress, caPool)
	if err != nil {
		log.Fatal(err)
	}

	svr := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/add-me-to-openziti", http.HandlerFunc(addToOpenZiti))
	mux.Handle("/", http.HandlerFunc(serveIndexHTML))
	mux.Handle("/description", http.HandlerFunc(showToken))
	mux.Handle("/download-token", http.HandlerFunc(downloadToken))

	go bootstrapReflectServer()

	svr.Handler = mux
	port := 18000
	ln := common.CreateUnderlayListener(port)
	log.Printf("Starting insecure server on %d\n", port)
	if err := svr.Serve(ln); err != nil {
		log.Fatal(err)

	}

	// go bootstrapReflectServer()

	hostingRouterName := erName
	serviceName := "serviceName"
	testerUsername := "admin"

	hostRouterIdent := getIdentityByName(client, hostingRouterName)
	webTestService := getServiceByName(client, serviceName)

	// // Create a service that "links" the dial and bind configs
	// createService(client, serviceName, []string{bindSvcConfig.ID, dialSvcConfig.ID})

	bindSP := createServicePolicy(client, "serviceName.bind", rest_model.DialBindBind, rest_model.Roles{"@" + *hostRouterIdent.ID}, rest_model.Roles{"@" + *webTestService.ID})
	defer func() { _ = deleteServicePolicyByID(client, bindSP.ID) }()
	fmt.Println("bind service policy is:", bindSP)

	testerIdent := getIdentityByName(client, testerUsername)

	dialSP := createServicePolicy(client, "serviceName.dial", rest_model.DialBindDial, rest_model.Roles{"@" + *testerIdent.ID}, rest_model.Roles{"@" + *webTestService.ID})
	defer func() { _ = deleteServicePolicyByID(client, dialSP.ID) }()

	fmt.Println("dial service policy is:", dialSP)

	// Create the tester identity
	ident := createRecreateIdentity(client, testerUsername, rest_model.IdentityTypeUser, false)

	// Enroll the identity
	identConfig := enrollIdentity(client, ident.Payload.Data.ID)

	// Create a json config file
	output, err := os.Create(testerUsername + ".json")
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create output config file")
	}
	defer func() {
		_ = output.Close()
		err = os.Remove(testerUsername + ".json")
		if err != nil {
			fmt.Println(err)
			log.Fatal("Failed to delete json config file")
		}
	}()
	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	fmt.Println("output is:", output)

	encErr := enc.Encode(&identConfig)
	if encErr != nil {
		fmt.Println(err)
		log.Fatal("Failed to generate encoded output")
	}

}

func runReflectClient() {
	// Delete reflect identity if it exists
	// create identity for reflect client
	testerUsername := "admin"
	ident := createRecreateIdentity(client, testerUsername, rest_model.IdentityTypeUser, false)

	// enroll identity for reflect client
	zitiConfig := enrollIdentity(client, ident.Payload.Data.ID)

	service := createService(client, "serviceName", nil)

	//create service policy Dial for client
	dialSP := createServicePolicy(client, "serviceName.dial", rest_model.DialBindDial, rest_model.Roles{"@" + ident.Payload.Data.ID}, rest_model.Roles{"@" + service.ID})
	defer func() { _ = deleteServicePolicyByID(client, dialSP.ID) }()

	//dial service
	svc.Client(zitiConfig, service.ID)

}

func bootstrapReflectServer() {
	serviceName := "myService"
	var serviceID string

	//delete reflect server indetity if needed
	// Delete reflect identity if it exists
	testerUsername := "admin"
	ident := createRecreateIdentity(client, testerUsername, rest_model.IdentityTypeUser, false)

	// enroll reflect server identity
	zitiConfig := enrollIdentity(client, ident.Payload.Data.ID)

	existingService := getServiceByName(client, serviceName)

	if existingService == nil {
		serviceID = createService(client, serviceName, nil).ID
		fmt.Println("Service created:", serviceID)
	} else {
		fmt.Println("Using existing service:", existingService.Name)
		serviceID = *existingService.ID
	}
	fmt.Println("Service ID is :", serviceID)

	// if len(serviceName) < 0 {
	// 	service = createService(client, serviceName, nil)
	// }
	// // service := createService(client, serviceName, nil)
	// fmt.Println("service je ovo: ", service)

	// bind reflect server service
	// serviceName := "basic.web.smoke.test.service"
	// erName := os.Getenv("ZITI_ROUTER_NAME")
	// if erName == "" {
	// 	erName = "ziti-edge-router"
	// }
	// hostingRouterName := erName
	// hostRouterIdent := getIdentityByName(client, hostingRouterName)
	// webTestService := getServiceByName(client, serviceName)
	bindSP := createServicePolicy(client, serviceName+".Bind", rest_model.DialBindBind, rest_model.Roles{ /*"@" + ident.Payload.Data.ID*/ }, rest_model.Roles{"@" + serviceName})
	//defer func() { _ = deleteServicePolicyByID(client, bindSP.ID) }()
	fmt.Println("bind service policy is:", bindSP)

	//then I have reflect server running

	//bind service
	svc.Server(zitiConfig, serviceID)

}

func serveIndexHTML(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func addToOpenZiti(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	email := r.Form.Get("email")
	log.Printf("Received email: %s", email)
	if email == "" {
		http.Error(w, "Invalid input. email form field not provided", http.StatusBadRequest)
		return
	}

	oidcProvider := r.URL.Query().Get("oidcProvider")
	if oidcProvider == "" {
		log.Printf("oidcProvider not provided. using default: %s", defaultProvider)
		oidcProvider = defaultProvider
	}
	log.Printf("inputs: %s %s", email, oidcProvider)

	createdIdentity := createRecreateIdentity(client, email, rest_model.IdentityTypeUser, false)
	jwtToken = getJWTToken(client, createdIdentity.Payload.Data.ID) // Store the JWT token

	fmt.Println("createdIdentity is: ", createdIdentity)

	http.Redirect(w, r, "/description?token="+createdIdentity.Payload.Data.ID, http.StatusSeeOther)
	// http.Redirect(w, r, "/description?token="+jwtToken, http.StatusSeeOther)
}

func showToken(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token not provided", http.StatusBadRequest)
		return
	}

	tmpl, err := template.ParseFiles("description.html")
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}

	data := struct {
		Token string
	}{
		Token: token,
	}

	w.Header().Set("Content-Type", "text/html")
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}

}

func downloadToken(w http.ResponseWriter, r *http.Request) {
	if jwtToken == "" {
		http.Error(w, "Token not available", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=token.jwt")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(jwtToken))
}

func getJWTToken(client *rest_management_api_client.ZitiEdgeManagement, identityID string) string {
	// Retrieve and return the JWT token for the given identity ID
	params := &identity.DetailIdentityParams{
		Context: context.Background(),
		ID:      identityID,
	}
	params.SetTimeout(30 * time.Second)
	resp, err := client.Identity.DetailIdentity(params, nil)
	if err != nil {
		log.Fatal(err)
	}
	return resp.GetPayload().Data.Enrollment.Ott.JWT
}

func createRecreateIdentity(client *rest_management_api_client.ZitiEdgeManagement, name string,
	identType rest_model.IdentityType, isAdmin bool) *identity.CreateIdentityCreated {
	i := &rest_model.IdentityCreate{
		Enrollment: &rest_model.IdentityCreateEnrollment{
			Ott: true,
		},
		IsAdmin:                   &isAdmin,
		Name:                      &name,
		RoleAttributes:            nil,
		ServiceHostingCosts:       nil,
		ServiceHostingPrecedences: nil,
		Tags:                      nil,
		Type:                      &identType,
	}
	p := identity.NewCreateIdentityParams()
	p.Identity = i
	p.Context = context.Background()
	fmt.Println("p identity is this: ", p.Identity)

	searchParam := identity.NewListIdentitiesParams()
	fmt.Println("searchParam is this: ", searchParam)
	filter := "name = \"" + name + "\""
	fmt.Println("filter is this: ", filter)
	searchParam.Filter = &filter
	fmt.Println("searchParam novi is this: ", searchParam)
	id, err := client.Identity.ListIdentities(searchParam, nil)
	fmt.Println("id is this: ", id)
	if err != nil {
		fmt.Println(err)
	}
	if id != nil && len(id.Payload.Data) > 0 {
		delParam := identity.NewDeleteIdentityParams()
		delParam.ID = *id.Payload.Data[0].ID
		_, err := client.Identity.DeleteIdentity(delParam, nil)
		if err != nil {
			fmt.Println(err)
		}
	}

	// Create the identity
	ident, err := client.Identity.CreateIdentity(p, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create the identity")
	}

	fmt.Println("ident payload is : ", ident.Payload)
	fmt.Println("ident payload data ID is : ", ident.Payload.Data.ID)
	time.Sleep(1 * time.Second)
	params := &identity.DetailIdentityParams{
		Context: context.Background(),
		ID:      ident.Payload.Data.ID,
	}
	params.SetTimeout(30 * time.Second)
	return ident
}

func createService(client *rest_management_api_client.ZitiEdgeManagement, name string, serviceConfigs []string) rest_model.CreateLocation {
	encryptOn := true // Default
	serviceCreate := &rest_model.ServiceCreate{
		Configs:            serviceConfigs,
		EncryptionRequired: &encryptOn,
		Name:               &name,
	}
	serviceParams := &service.CreateServiceParams{
		Service: serviceCreate,
		Context: context.Background(),
	}
	serviceParams.SetTimeout(30 * time.Second)

	// make code that checks if there is already that service name and just use that
	resp, err := client.Service.CreateService(serviceParams, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create " + name + " service")
	}
	return *resp.GetPayload().Data
}

func createServicePolicy(client *rest_management_api_client.ZitiEdgeManagement, name string, servType rest_model.DialBind, identityRoles rest_model.Roles, serviceRoles rest_model.Roles) rest_model.CreateLocation {

	// var resp *service_policy.CreateServicePolicyCreated

	defaultSemantic := rest_model.SemanticAllOf
	servicePolicy := &rest_model.ServicePolicyCreate{
		IdentityRoles: identityRoles,
		Name:          &name,
		Semantic:      &defaultSemantic,
		//ServiceRoles:  serviceRoles,
		Type: &servType,
	}
	params := &service_policy.CreateServicePolicyParams{
		Policy:  servicePolicy,
		Context: context.Background(),
	}
	fmt.Println("service policy is: ", servicePolicy)
	params.SetTimeout(30 * time.Second)

	// if len(name) > 0 {
	// 	fmt.Println("sps craeting:", name)
	// 	return *resp.GetPayload().Data

	// }
	// if name == "" {

	// }
	resp, err := client.ServicePolicy.CreateServicePolicy(params, nil)
	// a := fmt.Sprintf("*resp.GetPayload().Data je %T", resp.GetPayload().Data)
	// fmt.Println(a)
	if err == nil { // if err == nil {
		fmt.Println(err)
		return *resp.GetPayload().Data
		// TODO error, name must be unique!!!
		//log.Fatal("Failed to create the " + name + " service policy")
	}

	return rest_model.CreateLocation{}
}

func deleteServicePolicyByID(client *rest_management_api_client.ZitiEdgeManagement, id string) *service_policy.DeleteServicePolicyOK {
	deleteParams := &service_policy.DeleteServicePolicyParams{
		ID: id,
	}
	deleteParams.SetTimeout(30 * time.Second)
	resp, err := client.ServicePolicy.DeleteServicePolicy(deleteParams, nil)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}

func getIdentityByName(client *rest_management_api_client.ZitiEdgeManagement, name string) *rest_model.IdentityDetail {
	filter := "name=\"" + name + "\""
	params := &identity.ListIdentitiesParams{
		Filter:  &filter,
		Context: context.Background(),
	}
	params.SetTimeout(30 * time.Second)
	resp, err := client.Identity.ListIdentities(params, nil)
	if err != nil {
		log.Fatalf("Could not obtain an ID for the identity named %s", name)
		fmt.Println(err)
	}

	return resp.GetPayload().Data[0]
}

func getServiceByName(client *rest_management_api_client.ZitiEdgeManagement, name string) *rest_model.ServiceDetail {
	filter := "name=\"" + name + "\""
	params := &service.ListServicesParams{
		Filter:  &filter,
		Context: context.Background(),
	}
	params.SetTimeout(30 * time.Second)
	resp, err := client.Service.ListServices(params, nil)
	if err != nil {
		log.Fatalf("Could not obtain an ID for the service named %s", name)
		fmt.Println(err)
	}
	return resp.GetPayload().Data[0]
}

func enrollIdentity(client *rest_management_api_client.ZitiEdgeManagement, identityID string) *ziti.Config {
	// Get the identity object
	params := &identity.DetailIdentityParams{
		Context: context.Background(),
		ID:      identityID,
	}
	params.SetTimeout(30 * time.Second)
	resp, err := client.Identity.DetailIdentity(params, nil)

	if err != nil {
		log.Fatal(err)
	}

	// Enroll the identity
	tkn, _, err := enroll.ParseToken(resp.GetPayload().Data.Enrollment.Ott.JWT)
	if err != nil {
		log.Fatal(err)
	}

	flags := enroll.EnrollmentFlags{
		Token:  tkn,
		KeyAlg: "RSA",
	}
	conf, err := enroll.Enroll(flags)

	if err != nil {
		log.Fatal(err)
	}

	return conf
}

func deleteIdentityByID(client *rest_management_api_client.ZitiEdgeManagement, id string) *identity.DeleteIdentityOK {
	deleteParams := &identity.DeleteIdentityParams{
		ID: id,
	}
	deleteParams.SetTimeout(30 * time.Second)
	resp, err := client.Identity.DeleteIdentity(deleteParams, nil)
	if err != nil {
		fmt.Println(err)
	}
	return resp
}

//=====================================
// ziti edge delete identity reflect-server

// ziti edge delete identity reflect-client
// ziti edge delete serivce-policy reflect-client-bind
// ziti edge delete serivce-policy reflect-client-dial
// ziti edge delete service reflectService

// ziti edge create service reflectService --role-attributes reflect-service
// ziti edge create identity device reflect-client -a reflect.clients -o reflect-client.jwt
// ziti edge create identity device reflect-server -a reflect.servers -o reflect-server.jwt
// ziti edge enroll --jwt reflect-client.jwt
// ziti edge enroll --jwt reflect-server.jwt
// ziti edge create service-policy reflect-client-dial Dial --identity-roles '#reflect.clients' --service-roles '#reflect-service'
// ziti edge create service-policy reflect-client-bind Bind --identity-roles '#reflect.servers' --service-roles '#reflect-service'
//======================================

// deleteIdentity reflect-server
func deleteIdentityReflectServer(identityName string) {
	// logic to delete reflect-server
}

// deleteIdentity reflect-client
func deleteIdentityReflectClient(identityName string) {
	// logic to delete reflect-client
}

// deleteServicePolicy reflect-client-bind
func deleteServicePolicyReflectClientBind(policyName string) {
	// logic to delete reflect-client-bind
}

// deleteServicePolicy reflect-client-dial
func deleteServicePolicyReflectClientDial(policyName string) {
	// logic to delete reflect-client-dial
}

// deleteService reflectService
func deleteService(serviceName string) {
	// logic delete reflectService
}

// createService reflectService --role-attributes reflect-service
func createServiceReflectService(serviceName string, roleAttributes string) {
	// logic to create reflectService
}

// createIdentity device reflect-client -a reflect.clients -o reflect-client.jwt
func createIdentityReflectClient(identityName string, client string, jwt string) {
	// logic to create reflect-client
}

// createIdentity device reflect-server -a reflect.servers -o reflect-server.jwt
func createIdentityReflectServer(identityName string, server string, jwt string) {
	// logic to create reflect-server
}

// enrollIdentity --jwt reflect-client.jwt
func enrollIdentityReflectClient(jwt string) {
	// logic to enroll reflect-client
}

// enrollIdentity --jwt reflect-server.jwt
func enrollIdentityReflectServer(jwt string) {
	// logic to enroll reflect-server
}

// createServicePolicy reflect-client-dial Dial --identity-roles '#reflect.clients' --service-roles '#reflect-service'
func createServicePolicyReflectClientDial(policyName string, identityRoles string, serviceRoles string) {
	// logic to create service policy reflect-client-dial
}

// createServicePolicy reflect-client-bind Bind --identity-roles '#reflect.servers' --service-roles '#reflect-service'
func createServicePolicyReflectClientBind(policyName string, identityRoles string, serviceRoles string) {
	// logic to create reflect-client-bind
}

// func createIdentityOIDC(name string, email string,
// 	identType rest_model.IdentityType, isAdmin bool) *identity.CreateIdentityCreated {
// 	authPolicyId := os.Getenv("OPENZITI_AUTH_POLICY_ID")
// 	attrs := &rest_model.Attributes{"docker.whale.dialers"}

// 	i := &rest_model.IdentityCreate{
// 		AuthPolicyID:              &authPolicyId,
// 		ExternalID:                &email,
// 		IsAdmin:                   &isAdmin,
// 		Name:                      &name,
// 		RoleAttributes:            attrs,
// 		ServiceHostingCosts:       nil,
// 		ServiceHostingPrecedences: nil,
// 		Tags:                      nil,
// 		Type:                      &identType,
// 	}
// 	p := identity.NewCreateIdentityParams()
// 	p.Identity = i
// 	p.Context = context.Background()

// 	searchParam := identity.NewListIdentitiesParams()
// 	filter := "name contains \"" + email + "\""
// 	searchParam.Filter = &filter
// 	id, err := client.Identity.ListIdentities(searchParam, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	if id != nil && len(id.Payload.Data) > 0 {
// 		delParam := identity.NewDeleteIdentityParams()
// 		delParam.ID = *id.Payload.Data[0].ID
// 		_, err := client.Identity.DeleteIdentity(delParam, nil)
// 		if err != nil {
// 			fmt.Println(err)
// 		}
// 	}
// 	ident, err := client.Identity.CreateIdentity(p, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	fmt.Println("ident payload is : ", ident.Payload)
// 	fmt.Println("ident payload data ID is : ", ident.Payload.Data.ID)
// 	time.Sleep(1 * time.Second)
// 	params := &identity.DetailIdentityParams{
// 		Context: context.Background(),
// 		ID:      ident.Payload.Data.ID,
// 	}
// 	params.SetTimeout(30 * time.Second)
// 	resp, _ := client.Identity.DetailIdentity(params, nil)
// 	fmt.Println(resp.GetPayload().Data.Enrollment.Ott.JWT)

// 	return ident
// }
