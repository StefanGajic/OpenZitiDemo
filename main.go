package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
var client *rest_management_api_client.ZitiEdgeManagement
var jwtToken string

func init() {

	zitiAdminUsername := os.Getenv("OPENZITI_USER")
	zitiAdminPassword := os.Getenv("OPENZITI_PWD")
	ctrlAddress := os.Getenv("OPENZITI_CTRL")
	erName := os.Getenv("ZITI_ROUTER_NAME")
	if erName == "" {
		erName = "ziti-edge-router"
	}
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

	createService("reflectService", "reflect-service")
	createService("httpService", "reflect-service")
	createIdentity(rest_model.IdentityTypeDevice, "reflect-server", "reflect.servers")
	serverIdentity = enrollIdentity("reflect-server")

	createServicePolicy("reflect-client-dial", rest_model.DialBindDial, rest_model.Roles{"#reflect.clients"}, rest_model.Roles{"#reflect-service"})
	createServicePolicy("reflect-client-bind", rest_model.DialBindBind, rest_model.Roles{"#reflect.servers"}, rest_model.Roles{"#reflect-service"})

	go svc.Server(serverIdentity, "reflectService")
	port := 18000
	underlayListener := common.CreateUnderlayListener(port)
	zitifiedListener := common.CreateZitiListener(serverIdentity, "httpService")
	log.Printf("Starting insecure server on %d\n", port)
	go serveHTTP(underlayListener)
	go serveHTTP(zitifiedListener)

	baseURL := createMathUrl(18000, "http", "localhost")
	mathUrl := addMathParams(baseURL, os.Args[1], os.Args[2], os.Args[3])
	if len(os.Args) > 4 && os.Args[4] == "showcurl" {
		fmt.Println("This is the equivalent curl echo'ed from bash:")
		fmt.Printf("\n  echo Response: $(curl -sk '%s')\n\n", mathUrl)
	}

	go callTheApi(mathUrl)

	time.Sleep(600 * time.Second)
	// common.CreateServer()
}

func serveHTTP(listener net.Listener) {

	svr := &http.Server{}
	mux := http.NewServeMux()
	mux.Handle("/add-me-to-openziti", http.HandlerFunc(addToOpenZiti))
	mux.Handle("/", http.HandlerFunc(serveIndexHTML))
	mux.Handle("/description", http.HandlerFunc(showToken))
	mux.Handle("/download-token", http.HandlerFunc(downloadToken))
	mux.Handle("/hello", http.HandlerFunc(hello))
	mux.Handle("/domath", http.HandlerFunc(mathHandler))

	svr.Handler = mux

	if err := svr.Serve(listener); err != nil {
		log.Fatal(err)
	}
}

func createMathUrl(port int16, scheme, host string) string {
	return fmt.Sprintf("%s://%s:%d/domath", scheme, host, port)
}

func addMathParams(baseURL, input1, operator, input2 string) string {
	params := url.Values{}
	params.Set("input1", input1)
	params.Set("operator", operator)
	params.Set("input2", input2)

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func callTheApi(mathURL string) {
	req, err := http.NewRequest("GET", mathURL, nil)
	if err != nil {
		log.Fatalf("unable to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Error making the request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading the response: %v", err)
	}
	fmt.Println("Response:", string(body))
}

func hello(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "zitified hello from %s", host)
}

func mathHandler(w http.ResponseWriter, r *http.Request) {
	input1, err := strconv.ParseFloat(r.URL.Query().Get("input1"), 64)
	if err != nil {
		http.Error(w, "Invalid input1", http.StatusBadRequest)
		return
	}

	input2, err := strconv.ParseFloat(r.URL.Query().Get("input2"), 64)
	if err != nil {
		http.Error(w, "Invalid input2", http.StatusBadRequest)
		return
	}

	var result float64

	switch r.URL.Query().Get("operator") {
	case "+":
		result = input1 + input2
	case "-":
		result = input1 - input2
	case "*":
		result = input1 * input2
	case "/":
		if input2 == 0 {
			http.Error(w, "Division by zero not allowed", http.StatusBadRequest)
			return
		}
		result = input1 / input2
	default:
		http.Error(w, "Invalid operator, Use +, -, *, or /", http.StatusBadRequest)
		return
	}

	_, _ = fmt.Fprintf(w, "Result: %.2f", result)
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

	deleteIdentity(email)
	createdIdentity := createIdentity(rest_model.IdentityTypeUser, email, "reflect.servers")
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

func deleteIdentity(identityName string) {

	id := findIdentity(identityName)
	if id == "" {
		return
	}

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

func createService(serviceName string, attribute string) rest_model.CreateLocation {

	encryptOn := true
	serviceCreate := &rest_model.ServiceCreate{
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

	ident, err := client.Identity.CreateIdentity(p, nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create the identity")
	}

	return ident
}

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
