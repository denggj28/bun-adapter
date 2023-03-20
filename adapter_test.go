package bunadapter

import (
	"context"
	"database/sql"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	_ "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
	"strings"
	"testing"
)

const (
	rbacModelFile  = "examples/rbac_model.conf"
	rbacPolicyFile = "examples/rbac_policy.csv"
)

var (
	ctx = context.Background()
)

var (
	dataSourceName = map[string]string{
		// "sqlite3":  ":memory:",
		"mysql": "user:pass@tcp(192.168.88.11:3306)/casbin",
		// "postgres": "postgres://user:pass@192.168.88.11:5432/casbin?sslmode=disable",
		// "sqlserver": "sqlserver://sa:YourPassword@127.0.0.1:1433?database=sqlx_adapter_test&connection+timeout=30",
	}

	lines = []CasbinRule{
		{Ptype: "p", V0: "alice", V1: "data1", V2: "read"},
		{Ptype: "p", V0: "bob", V1: "data2", V2: "read"},
		{Ptype: "p", V0: "bob", V1: "data2", V2: "write"},
		{Ptype: "p", V0: "data2_admin", V1: "data1", V2: "read", V3: "test1", V4: "test2", V5: "test3"},
		{Ptype: "p", V0: "data2_admin", V1: "data2", V2: "write", V3: "test1", V4: "test2", V5: "test3"},
		{Ptype: "p", V0: "data1_admin", V1: "data2", V2: "write"},
		{Ptype: "g", V0: "alice", V1: "data2_admin"},
		{Ptype: "g", V0: "bob", V1: "data2_admin", V2: "test"},
		{Ptype: "g", V0: "bob", V1: "data1_admin", V2: "test2", V3: "test3", V4: "test4", V5: "test5"},
	}

	filter = Filter{
		Ptype: []string{"p"},
		V0:    []string{"bob", "data2_admin"},
		V1:    []string{"data1", "data2"},
		V2:    []string{"read", "write"},
	}
)

func getDB(driverName, dataSourceName string) *bun.DB {
	if driverName == "mysql" {
		sqldb, err := sql.Open("mysql", dataSourceName)
		if err != nil {
			panic(err)
		}
		db := bun.NewDB(sqldb, mysqldialect.New())
		db.AddQueryHook(bundebug.NewQueryHook())

		return db
	} else if driverName == "postgres" {
		sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dataSourceName)))
		db := bun.NewDB(sqldb, pgdialect.New())
		db.AddQueryHook(bundebug.NewQueryHook())

		return db
	} else {
		return nil
	}
}

func TestAdapters(t *testing.T) {
	for key, value := range dataSourceName {
		db := getDB(key, value)
		if db == nil {
			t.Fatalf("not supported driver: %s", key)
		}

		t.Logf(">>>>>>>>>>>>>> test [%s] start", key)

		t.Log("------------ testTableName start")
		testTableName(t, db)
		t.Log("------------ testTableName finish")

		t.Log("------------ testGenWhereCondition start")
		testGenWhereCondition(t, db)
		t.Log("------------ testGenWhereCondition finish")

		t.Log("------------ testGenFilteredWhereCondition start")
		testGenFilteredWhereCondition(t, db)
		t.Log("------------ testGenFilteredWhereCondition finish")

		t.Log("------------ testSaveLoad start")
		testSaveLoad(t, db, "")
		t.Log("------------ testSaveLoad finish")

		t.Log("------------ testAddPolicy start")
		testAddPolicy(t, db, "test_add_policy")
		t.Log("------------ testAddPolicy finish")

		t.Log("------------ testAutoSave start")
		testAutoSave(t, db, "test_auto_save")
		t.Log("------------ testAutoSave finish")

		t.Log("------------ testFilteredPolicy start")
		testFilteredPolicy(t, db, "test_filtered_policy")
		t.Log("------------ testFilteredPolicy finish")

		t.Log("------------ testUpdatePolicy start")
		testUpdatePolicy(t, db, "test_update_policy")
		t.Log("------------ testUpdatePolicy finish")

		t.Log("------------ testUpdatePolicies start")
		testUpdatePolicies(t, db, "test_update_policies")
		t.Log("------------ testUpdatePolicies finish")

		t.Log("------------ testUpdateFilteredPolicies start")
		testUpdateFilteredPolicies(t, db, "test_update_filtered_policies")
		t.Log("------------ testUpdateFilteredPolicies finish")

		t.Logf(">>>>>>>>>>>>>> test [%s] finish", key)
	}

}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	t.Logf("Policy: %v", myRes)

	m := make(map[string]struct{}, len(myRes))
	for _, record := range myRes {
		key := strings.Join(record, ",")
		m[key] = struct{}{}
	}

	if len(myRes) != len(res) {
		t.Errorf("Policy: %v\nsupposed to be %v", myRes, res)
	}

	for _, record := range res {
		key := strings.Join(record, ",")
		if _, ok := m[key]; !ok {
			t.Errorf("Policy: %v\nsupposed to be %v", myRes, res)
			break
		}
	}
}

func initPolicy(t *testing.T, db *bun.DB, tableName string) {
	e, _ := casbin.NewEnforcer(rbacModelFile, rbacPolicyFile)
	a, err := NewAdapterContext(ctx, db, tableName)
	if err != nil {
		t.Fatalf("NewAdapterContext test failed, err: %v", err)
	}

	err = a.SavePolicy(e.GetModel())
	if err != nil {
		t.Fatalf("SavePolicy test failed, err: %v", err)
	}

	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		t.Fatalf("LoadPolicy test failed, err: %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testTableName(t *testing.T, db *bun.DB) {
	_, err := NewAdapterContext(ctx, db, "casbin_rule")
	if err != nil {
		t.Fatalf("NewAdapterContext failed, err: %v", err)
	}
}

func testGenWhereCondition(t *testing.T, db *bun.DB) {
	_, err := NewAdapterContext(ctx, db)
	if err != nil {
		t.Fatalf("NewAdapterContext failed, err: %v", err)
	}

	for _, v := range lines {
		clause, args := genWhereCondition(&v)
		t.Logf("clause: %s\nargs: %v", clause, args)
	}
}

func testGenFilteredWhereCondition(t *testing.T, db *bun.DB) {
	_, err := NewAdapterContext(ctx, db)
	if err != nil {
		t.Fatalf("NewAdapterContext test failed, err: %v", err)
	}

	for _, v := range lines {
		clause, args := genFilteredWhereCondition(&v)
		t.Logf("clause: %s\nargs: %v", clause, args)
	}
}

func testSaveLoad(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)
	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testAutoSave(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)

	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)
	e.EnableAutoSave(false)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Errorf("%s test failed, err: %v", action, err)
		}
	}

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy1")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy1")
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	_, err = e.AddPolicies([][]string{{"alice_1", "data_1", "read_1"}, {"bob_1", "data_1", "write_1"}})
	logErr("AddPolicies1")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy2")
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy2")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy3")
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	_, err = e.AddPolicies([][]string{{"alice_2", "data_2", "read_2"}, {"bob_2", "data_2", "write_2"}})
	logErr("AddPolicies2")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy4")
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"},
		{"alice_2", "data_2", "read_2"}, {"bob_2", "data_2", "write_2"}})

	_, err = e.RemovePolicies([][]string{{"alice_2", "data_2", "read_2"}, {"bob_2", "data_2", "write_2"}})
	logErr("RemovePolicies")
	err = e.LoadPolicy()
	logErr("LoadPolicy5")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	_, err = e.RemovePolicy("alice", "data1", "write")
	logErr("RemovePolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy6")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	_, err = e.RemoveFilteredPolicy(0, "data2_admin")
	logErr("RemoveFilteredPolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy7")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testAddPolicy(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)
	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)

	_, err := e.AddPolicy("bob", "data1", "write")
	if err != nil {
		t.Fatalf("AddPolicy test failed: err: %v", err)
	}
}

func testFilteredPolicy(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)
	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Errorf("%s test failed, err: %v", action, err)
		}
	}

	err = e.LoadFilteredPolicy(&Filter{V0: []string{"alice"}})
	logErr("LoadFilteredPolicy alice")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Load only bob's policies
	err = e.LoadFilteredPolicy(&Filter{V0: []string{"bob"}})
	logErr("LoadFilteredPolicy bob")
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Load policies for data2_admin
	err = e.LoadFilteredPolicy(&Filter{V0: []string{"data2_admin"}})
	logErr("LoadFilteredPolicy data2_admin")
	testGetPolicy(t, e, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Load policies for alice and bob
	err = e.LoadFilteredPolicy(&Filter{V0: []string{"alice", "bob"}})
	logErr("LoadFilteredPolicy alice bob")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

	_, err = e.AddPolicy("bob", "data1", "write")
	logErr("AddPolicy")

	err = e.LoadFilteredPolicy(&filter)
	logErr("LoadFilteredPolicy filter")
	testGetPolicy(t, e, [][]string{{"bob", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdatePolicy(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)

	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)

	e.EnableAutoSave(true)
	_, err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	if err != nil {
		t.Fatalf("UpdatePolicy test failed, err: %v", err)
	}
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdatePolicies(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)

	a, _ := NewAdapterContext(ctx, db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)

	e.EnableAutoSave(true)
	e.UpdatePolicies([][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}}, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdateFilteredPolicies(t *testing.T, db *bun.DB, tableName string) {
	initPolicy(t, db, tableName)

	a, _ := NewAdapter(db, tableName)
	e, _ := casbin.NewEnforcer(rbacModelFile, a)

	e.EnableAutoSave(true)
	e.UpdateFilteredPolicies([][]string{{"alice", "data1", "write"}}, 0, "alice", "data1", "read")
	e.UpdateFilteredPolicies([][]string{{"bob", "data2", "read"}}, 0, "bob", "data2", "write")
	e.LoadPolicy()
	testGetPolicyWithoutOrder(t, e, [][]string{{"alice", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data2", "read"}})
}

func testGetPolicyWithoutOrder(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	// log.Print("Policy: \n", myRes)

	if !arrayEqualsWithoutOrder(myRes, res) {
		t.Error("Policy: \n", myRes, ", supposed to be \n", res)
	}
}

func arrayEqualsWithoutOrder(a [][]string, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[int]string)
	mapB := make(map[int]string)
	order := make(map[int]struct{})
	l := len(a)

	for i := 0; i < l; i++ {
		mapA[i] = util.ArrayToString(a[i])
		mapB[i] = util.ArrayToString(b[i])
	}

	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			if _, ok := order[j]; ok {
				if j == l-1 {
					return false
				} else {
					continue
				}
			}
			if mapA[i] == mapB[j] {
				order[j] = struct{}{}
				break
			} else if j == l-1 {
				return false
			}
		}
	}
	return true
}
