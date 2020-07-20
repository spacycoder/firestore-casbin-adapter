package firestoreadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/mmcloughlin/meow"
	"google.golang.org/api/iterator"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	ID    string `json:"id",firestore:"id"`
	PType string `json:"pType",firestore:"pType"`
	V0    string `json:"v0",firestore:"v0"`
	V1    string `json:"v1",firestore:"v1"`
	V2    string `json:"v2",firestore:"v2"`
	V3    string `json:"v3",firestore:"v3"`
	V4    string `json:"v4",firestore:"v4"`
	V5    string `json:"v5",firestore:"v5"`
}

type Adapter struct {
	collectionName  string
	firestoreClient *firestore.Client
	filtered        bool
}

// NewAdapter expects GOOGLE_APPLICATION_CREDENTIALS to be set(see https://firebase.google.com/docs/admin/setup/#initialize-without-parameters)
func NewAdapter(options ...Option) (*Adapter, error) {
	// create adapter and set default values
	a := &Adapter{collectionName: "casbin_rule", filtered: false}
	err := a.initCasbinDatabase()
	return a, err
}

/* func NewFilteredAdapter(options ...Option) (FilteredAdapter, error) {
	a := &adapter{collectionName: "casbin_rule", filtered: true}
	err := a.initCasbinDatabase()
	return a, err
}
*/
// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

func (a *Adapter) initCasbinDatabase() error {
	app, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("error initializing firebase: %v", err)
	}

	firestoreClient, err := app.Firestore(context.Background())
	if err != nil {
		return fmt.Errorf("error getting firestore client: %v", err)
	}

	a.firestoreClient = firestoreClient
	return nil
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.PType) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.PType)
	if len(r.V0) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V0)
	}
	if len(r.V1) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V1)
	}
	if len(r.V2) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V2)
	}
	if len(r.V3) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V3)
	}
	if len(r.V4) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V4)
	}
	if len(r.V5) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V5)
	}

	return sb.String()
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}

	it := a.firestoreClient.Collection(a.collectionName).DocumentRefs(context.Background())
	batch := a.firestoreClient.Batch()
	for {
		doc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		batch = batch.Delete(doc)
	}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			doc := a.firestoreClient.Collection(a.collectionName).Doc(line.ID)
			batch = batch.Set(doc, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			doc := a.firestoreClient.Collection(a.collectionName).Doc(line.ID)
			batch = batch.Set(doc, line)
		}
	}

	_, err := batch.Commit(context.Background())
	return err
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	fmt.Printf("Add Policy: %+v\n\n", line)
	doc := a.firestoreClient.Collection(a.collectionName).Doc(line.ID)
	_, err := doc.Set(context.Background(), &line)
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	batch := a.firestoreClient.Batch()
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)

		doc := a.firestoreClient.Collection(a.collectionName).Doc(line.ID)
		batch.Set(doc, rule)
	}

	_, err := batch.Commit(context.Background())
	return err
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	coll := a.firestoreClient.Collection(a.collectionName)
	it := coll.Documents(context.Background())

	for {
		doc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var line CasbinRule
		err = doc.DataTo(&line)
		if err != nil {
			return err
		}
		persist.LoadPolicyLine(line.String(), model)
	}

	a.filtered = false
	return nil
}

func (a *Adapter) Query() firestore.Query {
	return a.firestoreClient.Collection(a.collectionName).Query
}

func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}

	query := filter.(firestore.Query)
	it := query.Documents(context.Background())

	for {
		doc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var line CasbinRule
		err = doc.DataTo(&line)
		if err != nil {
			return err
		}
		persist.LoadPolicyLine(line.String(), model)
	}

	a.filtered = true
	return nil
}

func (a *Adapter) docID(id string) string {
	return a.collectionName + "/" + id
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	fmt.Printf("Policy to remove %+v\n", rule)
	fmt.Printf("Collection %+s \n\n", a.collectionName)
	doc := a.firestoreClient.Doc("casbin_rule/" + policyID(ptype, rule))
	_, err := doc.Delete(context.Background())
	if err == nil {
		fmt.Printf("error is null!! %s\n", doc.Path)
	}
	return err
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{PType: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}
	line.ID = policyID(ptype, rule)
	return line
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	query := a.firestoreClient.Collection(a.collectionName).Where("p_type", "==", ptype)

	it := query.Documents(context.Background())
	batch := a.firestoreClient.Batch()
	for {
		doc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		batch.Delete(doc.Ref)
	}

	_, err := batch.Commit(context.Background())
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.firestoreClient.Collection(a.collectionName).Where("p_type", "==", ptype)

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 && fieldValues[0-fieldIndex] != "" {
		query = query.Where("v0", "==", fieldValues[0-fieldIndex])
	}
	if fieldIndex <= 1 && idx > 1 && fieldValues[1-fieldIndex] != "" {
		query = query.Where("v1", "==", fieldValues[1-fieldIndex])
	}
	if fieldIndex <= 2 && idx > 2 && fieldValues[2-fieldIndex] != "" {
		query = query.Where("v2", "==", fieldValues[2-fieldIndex])
	}
	if fieldIndex <= 3 && idx > 3 && fieldValues[3-fieldIndex] != "" {
		query = query.Where("v3", "==", fieldValues[3-fieldIndex])
	}
	if fieldIndex <= 4 && idx > 4 && fieldValues[4-fieldIndex] != "" {
		query = query.Where("v4", "==", fieldValues[4-fieldIndex])
	}
	if fieldIndex <= 5 && idx > 5 && fieldValues[5-fieldIndex] != "" {
		query = query.Where("v5", "==", fieldValues[5-fieldIndex])
	}

	it := query.Documents(context.Background())

	batch := a.firestoreClient.Batch()
	for {
		doc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		batch.Delete(doc.Ref)
	}

	_, err := batch.Commit(context.Background())
	return err
}

type Option func(*Adapter)

func Collection(coll string) Option {
	return func(a *Adapter) {
		a.collectionName = coll
	}
}
