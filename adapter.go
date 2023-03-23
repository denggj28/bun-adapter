package bunadapter

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/uptrace/bun"
	"log"
	"runtime"
	"strings"
)

type CasbinRule struct {
	bun.BaseModel `bun:"table:casbin_rule,alias:r"`

	Id    int64  `bun:"id,pk,autoincrement"`
	Ptype string `bun:"ptype,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V0    string `bun:"v0,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V1    string `bun:"v1,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V2    string `bun:"v2,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V3    string `bun:"v3,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V4    string `bun:"v4,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
	V5    string `bun:"v5,type:varchar(100),nullzero,notnull,unique:casbin_uidx,default:''"`
}

type Adapter struct {
	ctx       context.Context
	isFilter  bool
	db        *bun.DB
	tableName string
}

func (a *Adapter) IsFiltered() bool {
	return a.isFilter
}

type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

func finalizer(a *Adapter) {
	if a.db == nil {
		return
	}

	err := a.db.Close()
	if err != nil {
		log.Printf("close bun adapter connection failed, err: %v", err)
	}
}

func NewAdapterContext(ctx context.Context, db *bun.DB, tableName ...string) (*Adapter, error) {
	a := &Adapter{
		ctx: ctx,
		db:  db,
	}

	if len(tableName) > 0 {
		a.tableName = tableName[0]
	}

	err := a.db.Ping()
	if err != nil {
		return nil, err
	}

	// create table
	err = a.createTable()
	if err != nil {
		return nil, err
	}

	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func NewAdapter(db *bun.DB, tableName ...string) (*Adapter, error) {
	return NewAdapterContext(context.Background(), db, tableName...)
}

func (a *Adapter) createTable() error {
	query := a.db.NewCreateTable().Model((*CasbinRule)(nil))
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	_, err := query.IfNotExists().Exec(a.ctx)

	return err
}

func (a *Adapter) dropTable() error {
	query := a.db.NewDropTable().Model((*CasbinRule)(nil))
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	_, err := query.IfExists().Exec(a.ctx)

	return err
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	p := []string{line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
	var lineText string

	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}

	err := persist.LoadPolicyLine(lineText, model)
	if err != nil {
		fmt.Println("load policy line: ", err)
	}
}

func (a *Adapter) LoadPolicy(model model.Model) error {
	lines := make([]*CasbinRule, 0, 64)

	query := a.db.NewSelect().Model(&lines)
	if a.tableName != "" {
		query = query.ModelTableExpr(fmt.Sprintf("%s AS r", a.tableName))
	}
	err := query.Scan(a.ctx)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func (a *Adapter) genPolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{Ptype: ptype}

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

	return line
}

func (a *Adapter) SavePolicy(model model.Model) error {
	err := a.dropTable()
	if err != nil {
		return err
	}

	err = a.createTable()
	if err != nil {
		return err
	}

	lines := make([]*CasbinRule, 0, 64)

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := a.genPolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := a.genPolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return nil
	}

	query := a.db.NewInsert().Model(&lines)
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	_, err = query.Exec(a.ctx)

	return err
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.genPolicyLine(ptype, rule)
	query := a.db.NewInsert().Model(line)
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	_, err := query.Exec(a.ctx)

	return err
}

func (a *Adapter) AddPolicies(sec, ptype string, rules [][]string) error {
	err := a.db.RunInTx(a.ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, rule := range rules {
			line := a.genPolicyLine(ptype, rule)
			query := tx.NewInsert().Model(line)
			if a.tableName != "" {
				query = query.ModelTableExpr(a.tableName)
			}
			_, errTx := query.Exec(ctx)
			if errTx != nil {
				return errTx
			}
		}

		return nil
	})

	return err
}

func genWhereCondition(line *CasbinRule) (string, []interface{}) {
	cond := "ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?"
	args := []interface{}{
		line.Ptype,
		line.V0,
		line.V1,
		line.V2,
		line.V3,
		line.V4,
		line.V5,
	}

	return cond, args
}

func (a *Adapter) RemovePolicy(set, ptype string, rule []string) error {
	line := a.genPolicyLine(ptype, rule)
	clause, args := genWhereCondition(line)
	query := a.db.NewDelete().Model(line)
	if a.tableName != "" {
		query.ModelTableExpr(a.tableName)
	}

	_, err := query.Where(clause, args...).Exec(a.ctx)
	return err
}

func (a *Adapter) RemovePolicies(sec, ptype string, rules [][]string) error {
	err := a.db.RunInTx(a.ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, rule := range rules {
			line := a.genPolicyLine(ptype, rule)
			clause, args := genWhereCondition(line)
			query := tx.NewDelete().Model(line)
			if a.tableName != "" {
				query.ModelTableExpr(a.tableName)
			}

			_, errTx := query.Where(clause, args...).Exec(ctx)
			if errTx != nil {
				return errTx
			}
		}

		return nil
	})

	return err
}

func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	filterValue, ok := filter.(*Filter)
	if !ok {
		return fmt.Errorf("invalid filter type")
	}

	lines := make([]*CasbinRule, 0, 64)
	fields := [7]struct {
		col string
		val []string
	}{
		{"ptype", filterValue.Ptype},
		{"v0", filterValue.V0},
		{"v1", filterValue.V1},
		{"v2", filterValue.V2},
		{"v3", filterValue.V3},
		{"v4", filterValue.V4},
		{"v5", filterValue.V5},
	}

	query := a.db.NewSelect().Model(&lines)
	if a.tableName != "" {
		query = query.ModelTableExpr(fmt.Sprintf("%s AS r", a.tableName))
	}

	for i := range fields {
		switch len(fields[i].val) {
		case 0:
			continue
		case 1:
			query = query.Where("? = ?", bun.Ident(fields[i].col), fields[i].val[0])
		default:
			query = query.Where("? IN (?)", bun.Ident(fields[i].col), bun.In(fields[i].val))
		}
	}

	err := query.Scan(a.ctx)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	a.isFilter = true

	return nil
}

func genFilteredWhereCondition(line *CasbinRule) (string, []interface{}) {
	var clauseSlice []string
	var args []interface{}

	fields := [7]struct {
		col string
		val string
	}{
		{"ptype", line.Ptype},
		{"v0", line.V0},
		{"v1", line.V1},
		{"v2", line.V2},
		{"v3", line.V3},
		{"v4", line.V4},
		{"v5", line.V5},
	}

	for i := range fields {
		if fields[i].val != "" {
			clauseSlice = append(clauseSlice, fmt.Sprintf("%s = ?", fields[i].col))
			args = append(args, fields[i].val)
		}
	}

	return strings.Join(clauseSlice, " AND "), args
}

func (a *Adapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	line := &CasbinRule{Ptype: ptype}

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && idx > 1 {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && idx > 2 {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && idx > 3 {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && idx > 4 {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && idx > 5 {
		line.V5 = fieldValues[5-fieldIndex]
	}

	query := a.db.NewDelete().Model(line)
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	clause, args := genFilteredWhereCondition(line)
	_, err := query.Where(clause, args...).Exec(a.ctx)

	return err
}

func (a *Adapter) UpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	oRule := a.genPolicyLine(ptype, oldRule)
	nRule := a.genPolicyLine(ptype, newRule)

	query := a.db.NewUpdate().Model(nRule)
	if a.tableName != "" {
		query = query.ModelTableExpr(a.tableName)
	}
	clause, args := genWhereCondition(oRule)
	_, err := query.
		Set("ptype = ?", nRule.Ptype).
		Set("v0 = ?", nRule.V0).
		Set("v1 = ?", nRule.V1).
		Set("v2 = ?", nRule.V2).
		Set("v3 = ?", nRule.V3).
		Set("v4 = ?", nRule.V4).
		Set("v5 = ?", nRule.V5).
		Where(clause, args...).Exec(a.ctx)

	return err
}

func (a *Adapter) UpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	err := a.db.RunInTx(a.ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for i, oldRule := range oldRules {
			nRule, oRule := a.genPolicyLine(ptype, newRules[i]), a.genPolicyLine(ptype, oldRule)
			query := tx.NewUpdate().Model(nRule)
			if a.tableName != "" {
				query = query.ModelTableExpr(a.tableName)
			}
			clause, args := genWhereCondition(oRule)
			_, errTx := query.
				Set("ptype = ?", nRule.Ptype).
				Set("v0 = ?", nRule.V0).
				Set("v1 = ?", nRule.V1).
				Set("v2 = ?", nRule.V2).
				Set("v3 = ?", nRule.V3).
				Set("v4 = ?", nRule.V4).
				Set("v5 = ?", nRule.V5).
				Where(clause, args...).Exec(ctx)

			if errTx != nil {
				return errTx
			}
		}

		return nil
	})

	return err
}

func (a *Adapter) UpdateFilteredPolicies(
	sec string,
	ptype string,
	newRules [][]string,
	fieldIndex int,
	fieldValues ...string,
) ([][]string, error) {
	line := &CasbinRule{Ptype: ptype}
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newR := make([]*CasbinRule, 0, len(newRules))
	oldR := make([]*CasbinRule, 0)
	for _, newRule := range newRules {
		newR = append(newR, a.genPolicyLine(ptype, newRule))
	}

	err := a.db.RunInTx(a.ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var (
			errTx error
		)

		selectQuery := tx.NewSelect().Model(&oldR)
		if a.tableName != "" {
			selectQuery = selectQuery.ModelTableExpr(fmt.Sprintf("%s AS r", a.tableName))
		}
		clause, args := genFilteredWhereCondition(line)
		errTx = selectQuery.Where(clause, args...).Scan(ctx)
		if errTx != nil {
			return errTx
		}

		deleteQuery := tx.NewDelete().Model(&oldR)
		if a.tableName != "" {
			deleteQuery = deleteQuery.ModelTableExpr(a.tableName)
		}
		_, errTx = deleteQuery.WherePK().Exec(ctx)
		if errTx != nil {
			return errTx
		}

		insertQuery := tx.NewInsert().Model(&newR)
		if a.tableName != "" {
			insertQuery = insertQuery.ModelTableExpr(a.tableName)
		}
		_, errTx = insertQuery.Exec(ctx)
		if errTx != nil {
			return errTx
		}

		return nil
	})

	oldPolicies := make([][]string, 0)
	for _, rule := range oldR {
		oldPolicies = append(oldPolicies, []string{rule.Ptype, rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5})
	}

	return oldPolicies, err
}
