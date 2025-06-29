// Code generated by ent, DO NOT EDIT.

package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/e2b-dev/infra/packages/shared/pkg/models/accesstoken"
	"github.com/e2b-dev/infra/packages/shared/pkg/models/user"
	"github.com/google/uuid"
)

// AccessTokenCreate is the builder for creating a AccessToken entity.
type AccessTokenCreate struct {
	config
	mutation *AccessTokenMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetAccessToken sets the "access_token" field.
func (atc *AccessTokenCreate) SetAccessToken(s string) *AccessTokenCreate {
	atc.mutation.SetAccessToken(s)
	return atc
}

// SetAccessTokenHash sets the "access_token_hash" field.
func (atc *AccessTokenCreate) SetAccessTokenHash(s string) *AccessTokenCreate {
	atc.mutation.SetAccessTokenHash(s)
	return atc
}

// SetAccessTokenPrefix sets the "access_token_prefix" field.
func (atc *AccessTokenCreate) SetAccessTokenPrefix(s string) *AccessTokenCreate {
	atc.mutation.SetAccessTokenPrefix(s)
	return atc
}

// SetAccessTokenLength sets the "access_token_length" field.
func (atc *AccessTokenCreate) SetAccessTokenLength(i int) *AccessTokenCreate {
	atc.mutation.SetAccessTokenLength(i)
	return atc
}

// SetAccessTokenMaskPrefix sets the "access_token_mask_prefix" field.
func (atc *AccessTokenCreate) SetAccessTokenMaskPrefix(s string) *AccessTokenCreate {
	atc.mutation.SetAccessTokenMaskPrefix(s)
	return atc
}

// SetAccessTokenMaskSuffix sets the "access_token_mask_suffix" field.
func (atc *AccessTokenCreate) SetAccessTokenMaskSuffix(s string) *AccessTokenCreate {
	atc.mutation.SetAccessTokenMaskSuffix(s)
	return atc
}

// SetName sets the "name" field.
func (atc *AccessTokenCreate) SetName(s string) *AccessTokenCreate {
	atc.mutation.SetName(s)
	return atc
}

// SetNillableName sets the "name" field if the given value is not nil.
func (atc *AccessTokenCreate) SetNillableName(s *string) *AccessTokenCreate {
	if s != nil {
		atc.SetName(*s)
	}
	return atc
}

// SetUserID sets the "user_id" field.
func (atc *AccessTokenCreate) SetUserID(u uuid.UUID) *AccessTokenCreate {
	atc.mutation.SetUserID(u)
	return atc
}

// SetCreatedAt sets the "created_at" field.
func (atc *AccessTokenCreate) SetCreatedAt(t time.Time) *AccessTokenCreate {
	atc.mutation.SetCreatedAt(t)
	return atc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (atc *AccessTokenCreate) SetNillableCreatedAt(t *time.Time) *AccessTokenCreate {
	if t != nil {
		atc.SetCreatedAt(*t)
	}
	return atc
}

// SetID sets the "id" field.
func (atc *AccessTokenCreate) SetID(u uuid.UUID) *AccessTokenCreate {
	atc.mutation.SetID(u)
	return atc
}

// SetUser sets the "user" edge to the User entity.
func (atc *AccessTokenCreate) SetUser(u *User) *AccessTokenCreate {
	return atc.SetUserID(u.ID)
}

// Mutation returns the AccessTokenMutation object of the builder.
func (atc *AccessTokenCreate) Mutation() *AccessTokenMutation {
	return atc.mutation
}

// Save creates the AccessToken in the database.
func (atc *AccessTokenCreate) Save(ctx context.Context) (*AccessToken, error) {
	atc.defaults()
	return withHooks(ctx, atc.sqlSave, atc.mutation, atc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (atc *AccessTokenCreate) SaveX(ctx context.Context) *AccessToken {
	v, err := atc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atc *AccessTokenCreate) Exec(ctx context.Context) error {
	_, err := atc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atc *AccessTokenCreate) ExecX(ctx context.Context) {
	if err := atc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (atc *AccessTokenCreate) defaults() {
	if _, ok := atc.mutation.Name(); !ok {
		v := accesstoken.DefaultName
		atc.mutation.SetName(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (atc *AccessTokenCreate) check() error {
	if _, ok := atc.mutation.AccessToken(); !ok {
		return &ValidationError{Name: "access_token", err: errors.New(`models: missing required field "AccessToken.access_token"`)}
	}
	if _, ok := atc.mutation.AccessTokenHash(); !ok {
		return &ValidationError{Name: "access_token_hash", err: errors.New(`models: missing required field "AccessToken.access_token_hash"`)}
	}
	if _, ok := atc.mutation.AccessTokenPrefix(); !ok {
		return &ValidationError{Name: "access_token_prefix", err: errors.New(`models: missing required field "AccessToken.access_token_prefix"`)}
	}
	if _, ok := atc.mutation.AccessTokenLength(); !ok {
		return &ValidationError{Name: "access_token_length", err: errors.New(`models: missing required field "AccessToken.access_token_length"`)}
	}
	if _, ok := atc.mutation.AccessTokenMaskPrefix(); !ok {
		return &ValidationError{Name: "access_token_mask_prefix", err: errors.New(`models: missing required field "AccessToken.access_token_mask_prefix"`)}
	}
	if _, ok := atc.mutation.AccessTokenMaskSuffix(); !ok {
		return &ValidationError{Name: "access_token_mask_suffix", err: errors.New(`models: missing required field "AccessToken.access_token_mask_suffix"`)}
	}
	if _, ok := atc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`models: missing required field "AccessToken.name"`)}
	}
	if _, ok := atc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user_id", err: errors.New(`models: missing required field "AccessToken.user_id"`)}
	}
	if _, ok := atc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user", err: errors.New(`models: missing required edge "AccessToken.user"`)}
	}
	return nil
}

func (atc *AccessTokenCreate) sqlSave(ctx context.Context) (*AccessToken, error) {
	if err := atc.check(); err != nil {
		return nil, err
	}
	_node, _spec := atc.createSpec()
	if err := sqlgraph.CreateNode(ctx, atc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	atc.mutation.id = &_node.ID
	atc.mutation.done = true
	return _node, nil
}

func (atc *AccessTokenCreate) createSpec() (*AccessToken, *sqlgraph.CreateSpec) {
	var (
		_node = &AccessToken{config: atc.config}
		_spec = sqlgraph.NewCreateSpec(accesstoken.Table, sqlgraph.NewFieldSpec(accesstoken.FieldID, field.TypeUUID))
	)
	_spec.Schema = atc.schemaConfig.AccessToken
	_spec.OnConflict = atc.conflict
	if id, ok := atc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := atc.mutation.AccessToken(); ok {
		_spec.SetField(accesstoken.FieldAccessToken, field.TypeString, value)
		_node.AccessToken = value
	}
	if value, ok := atc.mutation.AccessTokenHash(); ok {
		_spec.SetField(accesstoken.FieldAccessTokenHash, field.TypeString, value)
		_node.AccessTokenHash = value
	}
	if value, ok := atc.mutation.AccessTokenPrefix(); ok {
		_spec.SetField(accesstoken.FieldAccessTokenPrefix, field.TypeString, value)
		_node.AccessTokenPrefix = value
	}
	if value, ok := atc.mutation.AccessTokenLength(); ok {
		_spec.SetField(accesstoken.FieldAccessTokenLength, field.TypeInt, value)
		_node.AccessTokenLength = value
	}
	if value, ok := atc.mutation.AccessTokenMaskPrefix(); ok {
		_spec.SetField(accesstoken.FieldAccessTokenMaskPrefix, field.TypeString, value)
		_node.AccessTokenMaskPrefix = value
	}
	if value, ok := atc.mutation.AccessTokenMaskSuffix(); ok {
		_spec.SetField(accesstoken.FieldAccessTokenMaskSuffix, field.TypeString, value)
		_node.AccessTokenMaskSuffix = value
	}
	if value, ok := atc.mutation.Name(); ok {
		_spec.SetField(accesstoken.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := atc.mutation.CreatedAt(); ok {
		_spec.SetField(accesstoken.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if nodes := atc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		edge.Schema = atc.schemaConfig.AccessToken
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.UserID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.AccessToken.Create().
//		SetAccessToken(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.AccessTokenUpsert) {
//			SetAccessToken(v+v).
//		}).
//		Exec(ctx)
func (atc *AccessTokenCreate) OnConflict(opts ...sql.ConflictOption) *AccessTokenUpsertOne {
	atc.conflict = opts
	return &AccessTokenUpsertOne{
		create: atc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (atc *AccessTokenCreate) OnConflictColumns(columns ...string) *AccessTokenUpsertOne {
	atc.conflict = append(atc.conflict, sql.ConflictColumns(columns...))
	return &AccessTokenUpsertOne{
		create: atc,
	}
}

type (
	// AccessTokenUpsertOne is the builder for "upsert"-ing
	//  one AccessToken node.
	AccessTokenUpsertOne struct {
		create *AccessTokenCreate
	}

	// AccessTokenUpsert is the "OnConflict" setter.
	AccessTokenUpsert struct {
		*sql.UpdateSet
	}
)

// SetName sets the "name" field.
func (u *AccessTokenUpsert) SetName(v string) *AccessTokenUpsert {
	u.Set(accesstoken.FieldName, v)
	return u
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *AccessTokenUpsert) UpdateName() *AccessTokenUpsert {
	u.SetExcluded(accesstoken.FieldName)
	return u
}

// SetUserID sets the "user_id" field.
func (u *AccessTokenUpsert) SetUserID(v uuid.UUID) *AccessTokenUpsert {
	u.Set(accesstoken.FieldUserID, v)
	return u
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *AccessTokenUpsert) UpdateUserID() *AccessTokenUpsert {
	u.SetExcluded(accesstoken.FieldUserID)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(accesstoken.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *AccessTokenUpsertOne) UpdateNewValues() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(accesstoken.FieldID)
		}
		if _, exists := u.create.mutation.AccessToken(); exists {
			s.SetIgnore(accesstoken.FieldAccessToken)
		}
		if _, exists := u.create.mutation.AccessTokenHash(); exists {
			s.SetIgnore(accesstoken.FieldAccessTokenHash)
		}
		if _, exists := u.create.mutation.AccessTokenPrefix(); exists {
			s.SetIgnore(accesstoken.FieldAccessTokenPrefix)
		}
		if _, exists := u.create.mutation.AccessTokenLength(); exists {
			s.SetIgnore(accesstoken.FieldAccessTokenLength)
		}
		if _, exists := u.create.mutation.AccessTokenMaskPrefix(); exists {
			s.SetIgnore(accesstoken.FieldAccessTokenMaskPrefix)
		}
		if _, exists := u.create.mutation.AccessTokenMaskSuffix(); exists {
			s.SetIgnore(accesstoken.FieldAccessTokenMaskSuffix)
		}
		if _, exists := u.create.mutation.CreatedAt(); exists {
			s.SetIgnore(accesstoken.FieldCreatedAt)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *AccessTokenUpsertOne) Ignore() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *AccessTokenUpsertOne) DoNothing() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the AccessTokenCreate.OnConflict
// documentation for more info.
func (u *AccessTokenUpsertOne) Update(set func(*AccessTokenUpsert)) *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&AccessTokenUpsert{UpdateSet: update})
	}))
	return u
}

// SetName sets the "name" field.
func (u *AccessTokenUpsertOne) SetName(v string) *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetName(v)
	})
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *AccessTokenUpsertOne) UpdateName() *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateName()
	})
}

// SetUserID sets the "user_id" field.
func (u *AccessTokenUpsertOne) SetUserID(v uuid.UUID) *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetUserID(v)
	})
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *AccessTokenUpsertOne) UpdateUserID() *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateUserID()
	})
}

// Exec executes the query.
func (u *AccessTokenUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("models: missing options for AccessTokenCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *AccessTokenUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *AccessTokenUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("models: AccessTokenUpsertOne.ID is not supported by MySQL driver. Use AccessTokenUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *AccessTokenUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// AccessTokenCreateBulk is the builder for creating many AccessToken entities in bulk.
type AccessTokenCreateBulk struct {
	config
	err      error
	builders []*AccessTokenCreate
	conflict []sql.ConflictOption
}

// Save creates the AccessToken entities in the database.
func (atcb *AccessTokenCreateBulk) Save(ctx context.Context) ([]*AccessToken, error) {
	if atcb.err != nil {
		return nil, atcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(atcb.builders))
	nodes := make([]*AccessToken, len(atcb.builders))
	mutators := make([]Mutator, len(atcb.builders))
	for i := range atcb.builders {
		func(i int, root context.Context) {
			builder := atcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AccessTokenMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, atcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = atcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, atcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, atcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (atcb *AccessTokenCreateBulk) SaveX(ctx context.Context) []*AccessToken {
	v, err := atcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atcb *AccessTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := atcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atcb *AccessTokenCreateBulk) ExecX(ctx context.Context) {
	if err := atcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.AccessToken.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.AccessTokenUpsert) {
//			SetAccessToken(v+v).
//		}).
//		Exec(ctx)
func (atcb *AccessTokenCreateBulk) OnConflict(opts ...sql.ConflictOption) *AccessTokenUpsertBulk {
	atcb.conflict = opts
	return &AccessTokenUpsertBulk{
		create: atcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (atcb *AccessTokenCreateBulk) OnConflictColumns(columns ...string) *AccessTokenUpsertBulk {
	atcb.conflict = append(atcb.conflict, sql.ConflictColumns(columns...))
	return &AccessTokenUpsertBulk{
		create: atcb,
	}
}

// AccessTokenUpsertBulk is the builder for "upsert"-ing
// a bulk of AccessToken nodes.
type AccessTokenUpsertBulk struct {
	create *AccessTokenCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(accesstoken.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *AccessTokenUpsertBulk) UpdateNewValues() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(accesstoken.FieldID)
			}
			if _, exists := b.mutation.AccessToken(); exists {
				s.SetIgnore(accesstoken.FieldAccessToken)
			}
			if _, exists := b.mutation.AccessTokenHash(); exists {
				s.SetIgnore(accesstoken.FieldAccessTokenHash)
			}
			if _, exists := b.mutation.AccessTokenPrefix(); exists {
				s.SetIgnore(accesstoken.FieldAccessTokenPrefix)
			}
			if _, exists := b.mutation.AccessTokenLength(); exists {
				s.SetIgnore(accesstoken.FieldAccessTokenLength)
			}
			if _, exists := b.mutation.AccessTokenMaskPrefix(); exists {
				s.SetIgnore(accesstoken.FieldAccessTokenMaskPrefix)
			}
			if _, exists := b.mutation.AccessTokenMaskSuffix(); exists {
				s.SetIgnore(accesstoken.FieldAccessTokenMaskSuffix)
			}
			if _, exists := b.mutation.CreatedAt(); exists {
				s.SetIgnore(accesstoken.FieldCreatedAt)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *AccessTokenUpsertBulk) Ignore() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *AccessTokenUpsertBulk) DoNothing() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the AccessTokenCreateBulk.OnConflict
// documentation for more info.
func (u *AccessTokenUpsertBulk) Update(set func(*AccessTokenUpsert)) *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&AccessTokenUpsert{UpdateSet: update})
	}))
	return u
}

// SetName sets the "name" field.
func (u *AccessTokenUpsertBulk) SetName(v string) *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetName(v)
	})
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *AccessTokenUpsertBulk) UpdateName() *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateName()
	})
}

// SetUserID sets the "user_id" field.
func (u *AccessTokenUpsertBulk) SetUserID(v uuid.UUID) *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetUserID(v)
	})
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *AccessTokenUpsertBulk) UpdateUserID() *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateUserID()
	})
}

// Exec executes the query.
func (u *AccessTokenUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("models: OnConflict was set for builder %d. Set it on the AccessTokenCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("models: missing options for AccessTokenCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *AccessTokenUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
