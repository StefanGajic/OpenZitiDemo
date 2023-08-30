package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/openzitidemo/common"
	"github.com/openziti/edge-api/rest_management_api_client"
	"github.com/openziti/edge-api/rest_management_api_client/identity"
	"github.com/openziti/edge-api/rest_management_api_client/service"
	"github.com/openziti/edge-api/rest_management_api_client/service_policy"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
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

	svr.Handler = mux
	port := 18000
	ln := common.CreateUnderlayListener(port)
	log.Printf("Starting insecure server on %d\n", port)
	if err := svr.Serve(ln); err != nil {
		log.Fatal(err)
	}

	hostingRouterName := erName
	serviceName := "basic.web.smoke.test.service"
	testerUsername := "gotester"

	hostRouterIdent := getIdentityByName(client, hostingRouterName)
	webTestService := getServiceByName(client, serviceName)

	// // Create a service that "links" the dial and bind configs
	// createService(client, serviceName, []string{bindSvcConfig.ID, dialSvcConfig.ID})

	bindSP := createServicePolicy(client, "basic.web.smoke.test.service.bind", rest_model.DialBindBind, rest_model.Roles{"@" + *hostRouterIdent.ID}, rest_model.Roles{"@" + *webTestService.ID})
	defer func() { _ = deleteServicePolicyByID(client, bindSP.ID) }()
	fmt.Println("bind service policy is:", bindSP)

	testerIdent := getIdentityByName(client, testerUsername)

	dialSP := createServicePolicy(client, "basic.web.smoke.test.service.dial", rest_model.DialBindDial, rest_model.Roles{"@" + *testerIdent.ID}, rest_model.Roles{"@" + *webTestService.ID})
	defer func() { _ = deleteServicePolicyByID(client, dialSP.ID) }()

	fmt.Println("dial service policy is:", dialSP)

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

	createdIdentity := createIdentity(client, email, email, rest_model.IdentityTypeUser, false)
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

func createIdentity(client *rest_management_api_client.ZitiEdgeManagement, name string, email string,
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

	searchParam := identity.NewListIdentitiesParams()
	filter := "name contains \"" + email + "\""
	searchParam.Filter = &filter
	id, err := client.Identity.ListIdentities(searchParam, nil)
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

// func createService(client *rest_management_api_client.ZitiEdgeManagement, name string, serviceConfigs []string) rest_model.CreateLocation {
// 	encryptOn := true // Default
// 	serviceCreate := &rest_model.ServiceCreate{
// 		Configs:            serviceConfigs,
// 		EncryptionRequired: &encryptOn,
// 		Name:               &name,
// 	}
// 	serviceParams := &service.CreateServiceParams{
// 		Service: serviceCreate,
// 		Context: context.Background(),
// 	}
// 	serviceParams.SetTimeout(30 * time.Second)
// 	resp, err := client.Service.CreateService(serviceParams, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 		log.Fatal("Failed to create " + name + " service")
// 	}
// 	return *resp.GetPayload().Data
// }

func createServicePolicy(client *rest_management_api_client.ZitiEdgeManagement, name string, servType rest_model.DialBind, identityRoles rest_model.Roles, serviceRoles rest_model.Roles) rest_model.CreateLocation {

	defaultSemantic := rest_model.SemanticAllOf
	servicePolicy := &rest_model.ServicePolicyCreate{
		IdentityRoles: identityRoles,
		Name:          &name,
		Semantic:      &defaultSemantic,
		ServiceRoles:  serviceRoles,
		Type:          &servType,
	}
	params := &service_policy.CreateServicePolicyParams{
		Policy:  servicePolicy,
		Context: context.Background(),
	}
	params.SetTimeout(30 * time.Second)
	resp, err := client.ServicePolicy.CreateServicePolicy(params, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create the " + name + " service policy")
	}

	return *resp.GetPayload().Data
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
