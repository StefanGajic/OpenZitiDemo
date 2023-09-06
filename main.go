package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	common "example.com/openzitidemo/common"
	svc "example.com/openzitidemo/service"

	"github.com/openziti/edge-api/rest_management_api_client"
	"github.com/openziti/edge-api/rest_management_api_client/identity"
	"github.com/openziti/edge-api/rest_management_api_client/service"
	"github.com/openziti/edge-api/rest_management_api_client/service_policy"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
)

var serverIdentity *ziti.Config

func init() {

	zitiAdminUsername := os.Getenv("OPENZITI_USER")
	zitiAdminPassword := os.Getenv("OPENZITI_PWD")
	ctrlAddress := os.Getenv("OPENZITI_CTRL")
	erName := os.Getenv("ZITI_ROUTER_NAME")
	if erName == "" {
		erName = "ziti-edge-router"
	}
	// Authenticate with the controller
	caCerts, err := rest_util.GetControllerWellKnownCas(ctrlAddress)
	if err != nil {
		log.Fatal(err)
	}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}
	c, err := rest_util.NewEdgeManagementClientWithUpdb(zitiAdminUsername, zitiAdminPassword, ctrlAddress, caPool)
	if err != nil {
		log.Fatal(err)
	}
	client = c

}

func main() {

	deleteIdentity("reflect-server")
	deleteIdentity("reflect-client")
	deleteServicePolicy("reflect-client-bind")
	deleteServicePolicy("reflect-client-dial")
	deleteService("reflectService")
	deleteService("httpService")

	createService("reflectService", "reflect-service") //"reflect-service")
	createService("httpService", "reflect-service")
	// createIdentity(rest_model.IdentityTypeDevice, "reflect-client", "reflect.clients")
	createIdentity(rest_model.IdentityTypeDevice, "reflect-server", "reflect.servers")
	// clientIdentity := enrollIdentity("reflect-client")
	serverIdentity = enrollIdentity("reflect-server")

	createServicePolicy("reflect-client-dial", rest_model.DialBindDial, rest_model.Roles{"#reflect.clients"}, rest_model.Roles{"#reflect-service"})
	createServicePolicy("reflect-client-bind", rest_model.DialBindBind, rest_model.Roles{"#reflect.servers"}, rest_model.Roles{"#reflect-service"})

	go svc.Server(serverIdentity, "reflectService")
	// I dont want to start the client in the server
	// start the old server to deliver index page
	// start a client somethewrer else
	//svc.Client(clientIdentity, "reflectService")
	port := 18000
	underlayListener := common.CreateUnderlayListener(port)
	zitifiedListener := common.CreateZitiListener(serverIdentity, "httpService")
	log.Printf("Starting insecure server on %d\n", port)
	go serveHTTP(underlayListener)
	go serveHTTP(zitifiedListener)

	time.Sleep(600 * time.Second)
	// common.CreateServer()
}

var client *rest_management_api_client.ZitiEdgeManagement
var jwtToken string

func serveHTTP(listener net.Listener) {

	svr := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/add-me-to-openziti", http.HandlerFunc(addToOpenZiti))
	mux.Handle("/", http.HandlerFunc(serveIndexHTML))
	mux.Handle("/description", http.HandlerFunc(showToken))
	mux.Handle("/download-token", http.HandlerFunc(downloadToken))
	mux.Handle("/hello", http.HandlerFunc(hello))

	svr.Handler = mux

	if err := svr.Serve(listener); err != nil {
		log.Fatal(err)

	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "zitified hello from %s", host)
}

// add a func to take 2 params and do math! got sample cod with that, take 2 query perms and do whatever
// expose the math func now

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

	// (client *rest_management_api_client.ZitiEdgeManagement, name string, identType rest_model.IdentityType)

	// (identType rest_model.IdentityType, identityName string, attributes string)
	// createdIdentity := createIdentity(client, email, rest_model.IdentityTypeUser)
	// TODO fix this so it uses createIdentity
	createdIdentity := createRecreateIdentity(client, email, rest_model.IdentityTypeUser, false)
	jwtToken = getJWTToken(client, createdIdentity.Payload.Data.ID)
	fmt.Println("createdIdentity is: ", createdIdentity)

	http.Redirect(w, r, "/description?token="+createdIdentity.Payload.Data.ID, http.StatusSeeOther)
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
		RoleAttributes:            &rest_model.Attributes{"reflect.clients"},
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

func findIdentity(identityName string) string {
	searchParam := identity.NewListIdentitiesParams()
	filter := "name = \"" + identityName + "\""
	searchParam.Filter = &filter
	id, err := client.Identity.ListIdentities(searchParam, nil)
	if err != nil {
		fmt.Println(err)
	}
	if id != nil && len(id.Payload.Data) == 0 {
		return ""
	}
	return *id.Payload.Data[0].ID
}

// deleteIdentity reflect-server

func deleteIdentity(identityName string) {
	id := findIdentity(identityName)
	if id == "" {
		return
	}
	// logic to delete reflect-server
	deleteParams := &identity.DeleteIdentityParams{
		ID: id,
	}
	deleteParams.SetTimeout(30 * time.Second)
	_, err := client.Identity.DeleteIdentity(deleteParams, nil)
	if err != nil {
		fmt.Println(err)
	}
}

func findService(serviceName string) string {
	searchParam := service.NewListServicesParams()
	filter := "name=\"" + serviceName + "\""
	searchParam.Filter = &filter

	id, err := client.Service.ListServices(searchParam, nil)
	if err != nil {
		fmt.Println(err)
	}
	if id != nil && len(id.Payload.Data) == 0 {
		return ""
	}
	return *id.Payload.Data[0].ID
}

// deleteServicePolicy reflect-client-bind
func deleteService(serviceName string) {
	id := findService(serviceName)
	if id == "" {
		return
	}

	deleteParams := &service.DeleteServiceParams{
		ID: id,
	}
	deleteParams.SetTimeout(30 * time.Second)
	_, err := client.Service.DeleteService(deleteParams, nil)
	if err != nil {
		fmt.Println(err)
	}
}

func findServicePolicy(servicePolicyName string) string {
	searchParam := service_policy.NewListServicePoliciesParams()
	filter := "name=\"" + servicePolicyName + "\""
	searchParam.Filter = &filter

	id, err := client.ServicePolicy.ListServicePolicies(searchParam, nil)
	if err != nil {
		fmt.Println(err)
	}
	if id != nil && len(id.Payload.Data) == 0 {
		return ""
	}
	return *id.Payload.Data[0].ID
}

// deleteServicePolicy reflect-client-dial
func deleteServicePolicy(servicePolicyName string) {
	id := findServicePolicy(servicePolicyName)
	if id == "" {
		return
	}

	deleteParams := &service_policy.DeleteServicePolicyParams{
		ID: id,
	}
	deleteParams.SetTimeout(30 * time.Second)
	_, err := client.ServicePolicy.DeleteServicePolicy(deleteParams, nil)
	if err != nil {
		fmt.Println(err)
	}
}

// createService reflectService --role-attributes reflect-service
func createService(serviceName string, attribute string) rest_model.CreateLocation {
	//var serviceConfigs []string
	encryptOn := true // Default
	serviceCreate := &rest_model.ServiceCreate{
		//Configs:            serviceConfigs,
		EncryptionRequired: &encryptOn,
		Name:               &serviceName,
		RoleAttributes:     rest_model.Roles{attribute},
	}
	serviceParams := &service.CreateServiceParams{
		Service: serviceCreate,
		Context: context.Background(),
	}
	serviceParams.SetTimeout(30 * time.Second)
	resp, err := client.Service.CreateService(serviceParams, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create " + serviceName + " service")
	}
	return *resp.GetPayload().Data
}

// createIdentity device reflect-client -a reflect.clients -o reflect-client.jwt
func createIdentity(identType rest_model.IdentityType, identityName string, attributes string) *identity.CreateIdentityCreated {
	var isAdmin bool
	i := &rest_model.IdentityCreate{
		Enrollment: &rest_model.IdentityCreateEnrollment{
			Ott: true,
		},
		IsAdmin:                   &isAdmin,
		Name:                      &identityName,
		RoleAttributes:            &rest_model.Attributes{attributes},
		ServiceHostingCosts:       nil,
		ServiceHostingPrecedences: nil,
		Tags:                      nil,
		Type:                      &identType,
	}
	p := identity.NewCreateIdentityParams()
	p.Identity = i

	// Create the identity
	ident, err := client.Identity.CreateIdentity(p, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create the identity")
	}

	return ident
}

// enrollIdentity --jwt reflect-client.jwt
func enrollIdentity(identityName string) *ziti.Config {
	identityID := findIdentity(identityName)
	if identityID == "" {
		log.Fatal("identityID cant be found")
		return nil
	}
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

// createServicePolicy reflect-client-dial Dial --identity-roles '#reflect.clients' --service-roles '#reflect-service'
func createServicePolicy(name string, servType rest_model.DialBind, identityRoles rest_model.Roles, serviceRoles rest_model.Roles) rest_model.CreateLocation {
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
