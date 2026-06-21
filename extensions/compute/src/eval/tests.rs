use super::*;
use entity_ecf::ValueExt;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

/// Type alias for the dispatch closure used in handler-mode apply tests.
/// Matches `eval::DispatchExecuteFn<'static>` shape — kept local to avoid
/// reaching across the lifetime parameter.
type TestDispatchFn = Box<
    dyn Fn(
        &str,
        &str,
        Option<entity_capability::ResourceTarget>,
        Entity,
        Option<Entity>,
    ) -> ComputeValue,
>;

fn test_ctx() -> (HashMap<Hash, Entity>, String) {
    (HashMap::new(), TEST_PID.to_string())
}

/// Wildcard capability for tests that exercise tree reads but aren't
/// testing capability behavior (the §7.2 check requires SOME cap).
fn wildcard_test_cap() -> entity_capability::CapabilityToken {
    entity_capability::CapabilityToken {
        grants: entity_capability::wildcard_handler_grant(),
        granter: entity_capability::Granter::Single(Hash::compute("test", b"granter")),
        grantee: Hash::compute("test", b"grantee"),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

fn make_literal_int(n: i64) -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => entity_ecf::integer(n)
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_literal_str(s: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => entity_ecf::text(s)
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_literal_bool(b: bool) -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => Value::Bool(b)
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_literal_null() -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => Value::Null
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_scope_lookup(name: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "name" => entity_ecf::text(name)
    };
    Entity::new(TYPE_LOOKUP_SCOPE, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_tree_lookup(path: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "path" => entity_ecf::text(path)
    };
    Entity::new(TYPE_LOOKUP_TREE, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_hash_lookup(hash: Hash, path: Option<&str>) -> Entity {
    let mut fields = vec![
        (Value::Text("hash".into()), Value::Bytes(hash.to_bytes().to_vec())),
    ];
    if let Some(p) = path {
        fields.push((Value::Text("path".into()), entity_ecf::text(p)));
    }
    Entity::new(TYPE_LOOKUP_HASH, entity_ecf::to_ecf(&Value::Map(fields))).unwrap()
}

fn make_arithmetic(op: &str, left: Hash, right: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "left" => Value::Bytes(left.to_bytes().to_vec()),
        "op" => entity_ecf::text(op),
        "right" => Value::Bytes(right.to_bytes().to_vec())
    };
    Entity::new(TYPE_ARITHMETIC, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_compare(op: &str, left: Hash, right: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "left" => Value::Bytes(left.to_bytes().to_vec()),
        "op" => entity_ecf::text(op),
        "right" => Value::Bytes(right.to_bytes().to_vec())
    };
    Entity::new(TYPE_COMPARE, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_logic(op: &str, left: Hash, right: Option<Hash>) -> Entity {
    let mut fields = vec![
        (Value::Text("left".into()), Value::Bytes(left.to_bytes().to_vec())),
        (Value::Text("op".into()), entity_ecf::text(op)),
    ];
    if let Some(r) = right {
        fields.push((Value::Text("right".into()), Value::Bytes(r.to_bytes().to_vec())));
    }
    let data = Value::Map(fields);
    Entity::new(TYPE_LOGIC, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_if(cond: Hash, then: Hash, else_branch: Option<Hash>) -> Entity {
    let mut fields = vec![
        (Value::Text("condition".into()), Value::Bytes(cond.to_bytes().to_vec())),
        (Value::Text("then".into()), Value::Bytes(then.to_bytes().to_vec())),
    ];
    if let Some(e) = else_branch {
        fields.push((Value::Text("else".into()), Value::Bytes(e.to_bytes().to_vec())));
    }
    let data = Value::Map(fields);
    Entity::new(TYPE_IF, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_let(bindings: &[(&str, Hash)], body: Hash) -> Entity {
    let binding_arr: Vec<Value> = bindings
        .iter()
        .map(|(name, hash)| {
            Value::Map(vec![
                (Value::Text("name".into()), Value::Text(name.to_string())),
                (Value::Text("value".into()), Value::Bytes(hash.to_bytes().to_vec())),
            ])
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "bindings" => Value::Array(binding_arr),
        "body" => Value::Bytes(body.to_bytes().to_vec())
    };
    Entity::new(TYPE_LET, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_lambda(params: &[&str], body: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "body" => Value::Bytes(body.to_bytes().to_vec()),
        "params" => Value::Array(params.iter().map(|p| Value::Text(p.to_string())).collect())
    };
    Entity::new(TYPE_LAMBDA, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_apply_closure(fn_hash: Hash, args: &[(&str, Hash)]) -> Entity {
    let args_map: Vec<(Value, Value)> = args
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "args" => Value::Map(args_map),
        "fn" => Value::Bytes(fn_hash.to_bytes().to_vec())
    };
    Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_field(name: &str, entity_hash: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "entity" => Value::Bytes(entity_hash.to_bytes().to_vec()),
        "name" => entity_ecf::text(name)
    };
    Entity::new(TYPE_FIELD, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_construct(entity_type: &str, fields: &[(&str, Hash)]) -> Entity {
    let fields_map: Vec<(Value, Value)> = fields
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let data = entity_ecf::cbor_map! {
        "entity_type" => entity_ecf::text(entity_type),
        "fields" => Value::Map(fields_map)
    };
    Entity::new(TYPE_CONSTRUCT, entity_ecf::to_ecf(&data)).unwrap()
}

// --- Test helpers ---

fn eval_entity(cs: &dyn ContentStore, li: &dyn LocationIndex, entity: &Entity) -> ComputeValue {
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(cs, li, &included, &pid);
    evaluate(entity, &Scope::new(), &mut budget, &mut ctx)
}

// --- Literal tests ---

#[test]
fn test_literal_integer() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_int(42);
    let result = eval_entity(&cs, &li, &entity);
    assert_eq!(result.as_i128(), Some(42));
}

#[test]
fn test_literal_string() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_str("hello");
    let result = eval_entity(&cs, &li, &entity);
    match result {
        ComputeValue::Primitive(Value::Text(s)) => assert_eq!(s, "hello"),
        _ => panic!("expected string primitive, got {:?}", result),
    }
}

#[test]
fn test_literal_bool() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_bool(true);
    let result = eval_entity(&cs, &li, &entity);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        _ => panic!("expected bool"),
    }
}

#[test]
fn test_literal_null() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_null();
    let result = eval_entity(&cs, &li, &entity);
    match result {
        ComputeValue::Primitive(Value::Null) => {}
        _ => panic!("expected null"),
    }
}

// --- Scope lookup tests ---

#[test]
fn test_lookup_scope_found() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_scope_lookup("x");
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let mut scope = Scope::new();
    scope.set("x".into(), ComputeValue::Primitive(entity_ecf::integer(99)));
    let result = evaluate(&entity, &scope, &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(99));
}

#[test]
fn test_lookup_scope_not_found() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_scope_lookup("missing");
    let result = eval_entity(&cs, &li, &entity);
    assert!(result.is_error());
}

// --- Tree lookup tests ---

#[test]
fn test_lookup_tree_entity() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = "testpeer123456789012345678901234567890123456";

    let stored = Entity::new("app/data", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "value" => entity_ecf::integer(7)
    })).unwrap();
    let hash = cs.put(stored.clone()).unwrap();
    li.set(&format!("/{}/app/data/x", pid), hash);

    let lookup = make_tree_lookup("app/data/x");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid).with_capability(Some(&cap));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);

    match result {
        ComputeValue::Entity(e) => assert_eq!(e.entity_type, "app/data"),
        _ => panic!("expected entity, got {:?}", result),
    }
}

#[test]
fn test_lookup_tree_expression() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = "testpeer123456789012345678901234567890123456";

    let stored = make_literal_int(42);
    let hash = cs.put(stored.clone()).unwrap();
    li.set(&format!("/{}/app/cell/A1", pid), hash);

    let lookup = make_tree_lookup("app/cell/A1");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid).with_capability(Some(&cap));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(42));
}

// --- Arithmetic tests ---

#[test]
fn test_arithmetic_add() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(3);
    let right = make_literal_int(4);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("add", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(7));
}

#[test]
fn test_arithmetic_sub() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(10);
    let right = make_literal_int(3);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("sub", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(7));
}

#[test]
fn test_arithmetic_mul() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(6);
    let right = make_literal_int(7);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("mul", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(42));
}

#[test]
fn test_arithmetic_div_exact() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(10);
    let right = make_literal_int(2);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("div", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(5));
}

#[test]
fn test_arithmetic_div_float_promotion() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(7);
    let right = make_literal_int(2);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("div", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_f64(), Some(3.5));
}

#[test]
fn test_arithmetic_div_by_zero() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(10);
    let right = make_literal_int(0);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("div", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert!(result.is_error());
}

#[test]
fn test_arithmetic_mod() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(10);
    let right = make_literal_int(3);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_arithmetic("mod", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(1));
}

// --- Compare tests ---

#[test]
fn test_compare_eq() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(5);
    let right = make_literal_int(5);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_compare("eq", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        _ => panic!("expected bool true"),
    }
}

#[test]
fn test_compare_neq() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(5);
    let right = make_literal_int(6);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_compare("neq", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        _ => panic!("expected bool true"),
    }
}

#[test]
fn test_compare_lt() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let left = make_literal_int(3);
    let right = make_literal_int(5);
    let lh = cs.put(left).unwrap();
    let rh = cs.put(right).unwrap();
    let expr = make_compare("lt", lh, rh);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        _ => panic!("expected bool true"),
    }
}

// --- Logic tests ---

#[test]
fn test_logic_and() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let t = make_literal_bool(true);
    let f = make_literal_bool(false);
    let th = cs.put(t).unwrap();
    let fh = cs.put(f).unwrap();

    let expr = make_logic("and", th, Some(fh));
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(!b),
        _ => panic!("expected bool false"),
    }
}

#[test]
fn test_logic_or() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let t = make_literal_bool(true);
    let f = make_literal_bool(false);
    let th = cs.put(t).unwrap();
    let fh = cs.put(f).unwrap();

    let expr = make_logic("or", fh, Some(th));
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        _ => panic!("expected bool true"),
    }
}

#[test]
fn test_logic_not() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let t = make_literal_bool(true);
    let th = cs.put(t).unwrap();

    let expr = make_logic("not", th, None);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(!b),
        _ => panic!("expected bool false"),
    }
}

// --- If tests ---

#[test]
fn test_if_truthy() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let cond = make_literal_bool(true);
    let then = make_literal_int(1);
    let els = make_literal_int(2);
    let ch = cs.put(cond).unwrap();
    let th = cs.put(then).unwrap();
    let eh = cs.put(els).unwrap();

    let expr = make_if(ch, th, Some(eh));
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(1));
}

#[test]
fn test_if_falsy() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let cond = make_literal_bool(false);
    let then = make_literal_int(1);
    let els = make_literal_int(2);
    let ch = cs.put(cond).unwrap();
    let th = cs.put(then).unwrap();
    let eh = cs.put(els).unwrap();

    let expr = make_if(ch, th, Some(eh));
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(2));
}

#[test]
fn test_if_no_else() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let cond = make_literal_bool(false);
    let then = make_literal_int(1);
    let ch = cs.put(cond).unwrap();
    let th = cs.put(then).unwrap();

    let expr = make_if(ch, th, None);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Primitive(Value::Null) => {}
        _ => panic!("expected null for false if without else"),
    }
}

// --- Let tests ---

#[test]
fn test_let_simple() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let lit5 = make_literal_int(5);
    let lit5h = cs.put(lit5).unwrap();

    let body = make_scope_lookup("x");
    let bodyh = cs.put(body).unwrap();

    let expr = make_let(&[("x", lit5h)], bodyh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(5));
}

#[test]
fn test_let_sequential() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // let x = 5, y = x + 1, in y
    let lit5 = make_literal_int(5);
    let lit5h = cs.put(lit5).unwrap();

    let lit1 = make_literal_int(1);
    let lit1h = cs.put(lit1).unwrap();

    let lookup_x = make_scope_lookup("x");
    let lookup_xh = cs.put(lookup_x).unwrap();

    let add_expr = make_arithmetic("add", lookup_xh, lit1h);
    let add_h = cs.put(add_expr).unwrap();

    let body = make_scope_lookup("y");
    let bodyh = cs.put(body).unwrap();

    let expr = make_let(&[("x", lit5h), ("y", add_h)], bodyh);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(6));
}

// --- Lambda / Closure tests ---

#[test]
fn test_lambda_produces_closure() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let body = make_scope_lookup("x");
    let bodyh = cs.put(body).unwrap();

    let lambda = make_lambda(&["x"], bodyh);
    let result = eval_entity(&cs, &li, &lambda);
    match result {
        ComputeValue::Closure(c) => {
            assert_eq!(c.params, vec!["x"]);
            assert_eq!(c.body, bodyh);
        }
        _ => panic!("expected closure"),
    }
}

#[test]
fn test_apply_closure() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // lambda(x) -> x + 1, applied to 5
    let lookup_x = make_scope_lookup("x");
    let lookup_xh = cs.put(lookup_x).unwrap();

    let lit1 = make_literal_int(1);
    let lit1h = cs.put(lit1).unwrap();

    let body = make_arithmetic("add", lookup_xh, lit1h);
    let bodyh = cs.put(body).unwrap();

    let lambda = make_lambda(&["x"], bodyh);
    let _lambda_h = cs.put(lambda.clone()).unwrap();

    // We need the closure entity, not the lambda. Evaluate lambda first.
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let closure_val = evaluate(&lambda, &Scope::new(), &mut budget, &mut ctx);

    let closure_entity = match &closure_val {
        ComputeValue::Closure(c) => c.to_entity(),
        _ => panic!("expected closure"),
    };
    let closure_hash = cs.put(closure_entity).unwrap();

    let arg = make_literal_int(5);
    let argh = cs.put(arg).unwrap();

    let apply = make_apply_closure(closure_hash, &[("x", argh)]);

    let mut budget2 = Budget::default_budget();
    let mut ctx2 = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&apply, &Scope::new(), &mut budget2, &mut ctx2);
    assert_eq!(result.as_i128(), Some(6));
}

// --- Field tests ---

#[test]
fn test_field_extract() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Store a non-compute entity at a tree path — field extraction works
    // on entities returned by tree lookup (which bypasses D2 hash scoping).
    let target = Entity::new("app/person", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "age" => entity_ecf::integer(30),
        "name" => entity_ecf::text("Alice")
    })).unwrap();
    let th = cs.put(target).unwrap();
    li.set(&format!("/{}/app/people/alice", TEST_PID), th);

    // Use compute/lookup/tree to get the entity, then compute/field to extract
    let tree_lookup = make_tree_lookup("app/people/alice");
    let tree_lookup_h = cs.put(tree_lookup).unwrap();

    let field_expr = make_field("name", tree_lookup_h);
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&field_expr, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Primitive(Value::Text(s)) => assert_eq!(s, "Alice"),
        _ => panic!("expected string primitive, got {:?}", result),
    }
}

#[test]
fn test_field_not_found() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let target = Entity::new("app/data", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "x" => entity_ecf::integer(1)
    })).unwrap();
    let th = cs.put(target).unwrap();
    li.set(&format!("/{}/app/data/item", TEST_PID), th);

    let tree_lookup = make_tree_lookup("app/data/item");
    let tree_lookup_h = cs.put(tree_lookup).unwrap();

    let field_expr = make_field("missing", tree_lookup_h);
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&field_expr, &Scope::new(), &mut budget, &mut ctx);
    assert!(result.is_error());
}

/// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §2 (N.5 / F9 manifestation A):
/// `compute/field` must operate on *the value produced by evaluating its target*
/// — entity or record/map value — so chained navigation composes. Two-level
/// `field(field(person, "user"), "name")` over an entity whose `user` field is
/// a nested record must succeed.
#[test]
fn test_field_chain_through_record_value() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // app/person with a nested record-valued `user` field
    let person = Entity::new(
        "app/person",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "user" => Value::Map(vec![
                (Value::Text("name".into()), Value::Text("Alice".into())),
                (Value::Text("threshold".into()), entity_ecf::integer(42)),
            ])
        }),
    )
    .unwrap();
    let ph = cs.put(person).unwrap();
    li.set(&format!("/{}/app/people/alice", TEST_PID), ph);

    // Inner: field(tree_lookup("app/people/alice"), "user") → Primitive(Map)
    let tree_lookup_h = cs.put(make_tree_lookup("app/people/alice")).unwrap();
    let inner_field_h = cs.put(make_field("user", tree_lookup_h)).unwrap();
    // Outer: field(inner, "name") — target is a Primitive(Map), must compose.
    let outer_field = make_field("name", inner_field_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&outer_field, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Primitive(Value::Text(s)) => assert_eq!(s, "Alice"),
        other => panic!(
            "expected nested field navigation to compose, got {:?}",
            other
        ),
    }
}

/// PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE §2 (N.5 / F9 manifestation A):
/// `field(index(arr, 0), "k")` — extracting a field from an array element that
/// is itself a record/map value — must also compose.
#[test]
fn test_field_chain_through_index_of_records() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // tree value: an array of record-valued items
    let coll = Entity::new(
        "app/collection",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "items" => Value::Array(vec![
                Value::Map(vec![(Value::Text("k".into()), Value::Text("v0".into()))]),
                Value::Map(vec![(Value::Text("k".into()), Value::Text("v1".into()))]),
            ])
        }),
    )
    .unwrap();
    let ch = cs.put(coll).unwrap();
    li.set(&format!("/{}/app/items", TEST_PID), ch);

    let tree_h = cs.put(make_tree_lookup("app/items")).unwrap();
    let items_field_h = cs.put(make_field("items", tree_h)).unwrap();

    // compute/index { array: items_field, index: literal(0) }
    let zero_h = cs.put(make_literal_int(0)).unwrap();
    let index_expr = Entity::new(
        TYPE_INDEX,
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "array" => Value::Bytes(items_field_h.to_bytes().to_vec()),
            "index" => Value::Bytes(zero_h.to_bytes().to_vec())
        }),
    )
    .unwrap();
    let index_h = cs.put(index_expr).unwrap();

    let outer_field = make_field("k", index_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&outer_field, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Primitive(Value::Text(s)) => assert_eq!(s, "v0"),
        other => panic!("expected field-of-index composition, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// v3.19c regression tests — construct kind-tagged field encoding + navigation
// unwrap (§2.3 A.2/A.3; PROPOSAL-COMPUTE-V3.19C-CAPTURED-STATE-CLOSEOUT Part A).
// ---------------------------------------------------------------------------

/// v3.19c Part A navigation vector (A.3 / A.5): navigation chains MUST compose
/// transparently through compute-constructed entities. The construct produces
/// kind-tagged fields; `compute/field` unwraps them on the read side.
///
/// `field(field(construct(app/wrapper, {inner: construct(app/user, {name: "alice"})}), "inner"), "name") == "alice"`
#[test]
fn test_v319c_navigation_chain_through_construct() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // inner: construct(app/user, {name: "alice"})
    let name_lit_h = cs.put(make_literal_str("alice")).unwrap();
    let inner_construct = make_construct("app/user", &[("name", name_lit_h)]);
    let inner_h = cs.put(inner_construct).unwrap();

    // outer: construct(app/wrapper, {inner: <inner_construct>})
    let outer_construct = make_construct("app/wrapper", &[("inner", inner_h)]);
    let outer_h = cs.put(outer_construct).unwrap();

    // field(<outer>, "inner") — must unwrap kind:"entity" to the inner entity
    let inner_field = make_field("inner", outer_h);
    let inner_field_h = cs.put(inner_field).unwrap();

    // field(<inner_field>, "name") — must unwrap kind:"value" to "alice"
    let name_field = make_field("name", inner_field_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&name_field, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Primitive(Value::Text(s)) => assert_eq!(s, "alice"),
        other => panic!(
            "expected nested-navigation through constructed entities to yield \"alice\", got {:?}",
            other
        ),
    }
}

/// v3.19c Part A — read side closes the disambiguation: navigating through a
/// constructed entity's kind:"entity" field returns the *entity* (not the bare
/// hash bytes), so the next navigation step composes via N3's entity path.
#[test]
fn test_v319c_field_unwrap_kind_entity_resolves_to_entity() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let name_lit_h = cs.put(make_literal_str("bob")).unwrap();
    let inner = make_construct("app/user", &[("name", name_lit_h)]);
    let inner_h = cs.put(inner).unwrap();
    let outer = make_construct("app/wrapper", &[("inner", inner_h)]);
    let outer_h = cs.put(outer).unwrap();

    // field(<outer>, "inner") — the read-side unwrap must produce an Entity
    // (ComputeValue::Entity), not a bare 33-byte Primitive(Bytes).
    let inner_field = make_field("inner", outer_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&inner_field, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Entity(e) => assert_eq!(e.entity_type, "app/user"),
        other => panic!(
            "expected kind:entity field unwrap to ComputeValue::Entity(app/user), got {:?}",
            other
        ),
    }
}

/// v3.19c α (revised): a compute-constructed entity is **byte-
/// identical** to a hand-built (`Entity::new`) equivalent. The materialized
/// constructed entity follows V7 §1.4 (entity refs are bare `system/hash`
/// byte strings; primitives inline). This is the validate-peer hash-agreement
/// gate — same materialized hash three-way; same hash whether the entity
/// came through `compute/construct` or hand-built outside compute.
///
/// (Inverted from the prior-draft "differs_from_hand_built" test: the spec's
/// cross-path-determinism note has been **withdrawn** in the α revision.)
#[test]
fn test_v319c_materialized_construct_equals_hand_built() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let name_lit_h = cs.put(make_literal_str("alice")).unwrap();
    let constructed_expr = make_construct("app/user", &[("name", name_lit_h)]);
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let constructed = match evaluate(&constructed_expr, &Scope::new(), &mut budget, &mut ctx) {
        ComputeValue::Entity(e) => e,
        other => panic!("expected entity, got {:?}", other),
    };

    // Hand-built equivalent — same type, same data shape.
    let hand_built = Entity::new(
        "app/user",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") }),
    )
    .unwrap();

    assert_eq!(
        constructed.content_hash, hand_built.content_hash,
        "v3.19c α: compute-constructed materialized form MUST be byte-\
         identical to hand-built (the validate-peer hash-agreement gate)"
    );
    assert_eq!(constructed.data, hand_built.data, "data bytes must agree");
}

/// v3.19c α — primitive fields are **bare** in the materialized data (no
/// kind tags). Locks the V7 §1.4 form so any drift in the encoder is caught.
#[test]
fn test_v319c_construct_primitive_fields_are_bare() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let n_h = cs.put(make_literal_str("alice")).unwrap();
    let a_h = cs.put(make_literal_int(30)).unwrap();
    let expr = make_construct("app/user", &[("name", n_h), ("age", a_h)]);
    let result = eval_entity(&cs, &li, &expr);
    let entity = match result {
        ComputeValue::Entity(e) => e,
        other => panic!("expected entity, got {:?}", other),
    };
    let data = decode_data(&entity).unwrap();
    assert_eq!(
        data.get("name").and_then(|v| v.as_text()),
        Some("alice"),
        "primitive 'name' field must be bare per V7 §1.4 — no kind tag"
    );
    assert_eq!(
        data.get("age").and_then(|v| v.as_i64()),
        Some(30),
        "primitive 'age' field must be bare per V7 §1.4 — no kind tag"
    );
}

/// v3.19c α — an entity-valued construct field is materialized as a **bare
/// 33-byte `system/hash` reference** in the outer entity's data (per V7 §1.4);
/// the inner entity is residented in the content store so navigation can
/// resolve it. Locks the entity-valued field's wire shape.
#[test]
fn test_v319c_construct_entity_field_is_bare_hash_ref() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let inner_name_h = cs.put(make_literal_str("alice")).unwrap();
    let inner = make_construct("app/user", &[("name", inner_name_h)]);
    let inner_h = cs.put(inner).unwrap();
    let outer = make_construct("app/wrapper", &[("inner", inner_h)]);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&outer, &Scope::new(), &mut budget, &mut ctx);
    let outer_entity = match result {
        ComputeValue::Entity(e) => e,
        other => panic!("expected entity, got {:?}", other),
    };
    let data = decode_data(&outer_entity).unwrap();
    let inner_ref = data.get("inner").expect("inner field present");
    let bytes = match inner_ref {
        Value::Bytes(b) => b,
        other => panic!("inner must be bare bytes, got {:?}", other),
    };
    // The bare bytes IS the hash of the bare-materialized inner entity.
    // Compare structurally (algorithm || digest) — no fixed-length check per
    // arch 39bc8a2 / V7 §1.2 (system/hash is variable-length, extensible).
    let hand_built_inner = Entity::new(
        "app/user",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") }),
    )
    .unwrap();
    assert_eq!(
        bytes.as_slice(),
        hand_built_inner.content_hash.to_bytes().as_slice(),
        "the bare hash in 'inner' must equal the hand-built inner's content_hash \
         (structural byte equality — no fixed-size assumption)"
    );
}

/// v3.19c α + N3 ruling (arch `6e73d3d`) — **read-back nav
/// returns the hash, not an auto-resolved entity.** The prior "33-byte ⇒
/// auto-resolve" heuristic was shape-sniffing (N3 forbids it: misfires on a
/// real 33-byte bytes value). On a bare materialized entity stored in the
/// tree (and re-read in a fresh eval — *not* in-flight from this construct),
/// `compute/field` on a `system/hash`-typed field MUST return the bare hash
/// as `Primitive(Bytes(33))`. The caller follows the ref via explicit
/// `compute/lookup/hash`.
///
/// This is the regression detector arch flagged: today's
/// `v319c_construct_navigation_chain` exercises the *in-flight* chain (the
/// constructing eval still has the typed value in `ctx.constructed_in_flight`),
/// not the read-back path. This vector covers the read-back path explicitly
/// so the auto-resolve heuristic can't sneak back in.
#[test]
fn test_v319c_readback_navigation_returns_hash() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Hand-build an outer entity whose `inner` field is a bare 33-byte
    // `system/hash` reference. The inner is in the content store; we don't
    // care what's there — the point is that field(outer, "inner") MUST
    // return the bare bytes, not auto-resolve.
    let inner_hand_built = Entity::new(
        "app/user",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") }),
    )
    .unwrap();
    let inner_h = cs.put(inner_hand_built.clone()).unwrap();

    let outer_hand_built = Entity::new(
        "app/wrapper",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "inner" => Value::Bytes(inner_h.to_bytes().to_vec())
        }),
    )
    .unwrap();
    let outer_h = cs.put(outer_hand_built.clone()).unwrap();
    li.set(&format!("/{}/app/data/wrapped", TEST_PID), outer_h);

    // Fresh eval — `ctx.constructed_in_flight` is empty; the outer is read
    // back from the tree (case 2 in extract_field). N3: bare bytes return.
    let tree_lookup_h = cs.put(make_tree_lookup("app/data/wrapped")).unwrap();
    let inner_field = make_field("inner", tree_lookup_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&inner_field, &Scope::new(), &mut budget, &mut ctx);

    match result {
        ComputeValue::Primitive(Value::Bytes(b)) => {
            // Structural byte equality (crypto-agile per arch 39bc8a2 / V7
            // §1.2): the returned bytes MUST be byte-equal to the inner
            // entity's content_hash on the wire (`algorithm || digest`).
            // No fixed-length check — `system/hash` is variable-length with
            // an extensible LEB128 varint format code; "33 bytes" is just
            // today's `ecfv1-sha256` accident.
            assert_eq!(
                b.as_slice(),
                inner_h.to_bytes().as_slice(),
                "read-back nav on a system/hash field MUST return the field's \
                 hash unchanged (N3); structural byte equality expected"
            );
        }
        ComputeValue::Entity(e) => panic!(
            "N3 violation: read-back nav auto-resolved to Entity({}) instead \
             of returning the bare hash. Any shape/length heuristic on bytes \
             has crept back in — see extract_field.",
            e.entity_type
        ),
        other => panic!(
            "expected Primitive(Bytes) for read-back hash field, got {:?}",
            other
        ),
    }
}

/// v3.19c + §3.5 inline-vs-handler equivalence (regression detector found
/// during Rust's coherence pass on the v3.19c cut). `compute/construct`
/// inline and `compute/apply{path:"system/compute/builtins/construct"}` MUST
/// produce identical content hashes (§3.5 spec MUST). Without this test, a
/// future change could update one path's encoder and silently diverge the
/// hashes — exactly the v3.19c-N5-style determinism hole, at the inline-vs-
/// builtin boundary.
#[test]
fn test_v319c_inline_vs_builtin_construct_hash_agreement() {
    use crate::builtins::{dispatch_builtin_alias, BUILTIN_CONSTRUCT};
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Build two construct paths over identical input — name="alice", age=30 —
    // and compare the constructed entity's content hash.
    let name_lit_h = cs.put(make_literal_str("alice")).unwrap();
    let age_lit_h = cs.put(make_literal_int(30)).unwrap();
    let type_lit_h = cs.put(make_literal_str("app/user")).unwrap();

    // Inline form via compute/construct.
    let inline_expr = make_construct("app/user", &[("name", name_lit_h), ("age", age_lit_h)]);
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let inline_result = evaluate(&inline_expr, &Scope::new(), &mut budget, &mut ctx);
    let inline_hash = match inline_result {
        ComputeValue::Entity(e) => e.content_hash,
        other => panic!("inline construct didn't return entity: {:?}", other),
    };

    // Builtin handler form via dispatch_builtin_alias("construct", …).
    let args: Vec<(String, Hash)> = vec![
        ("entity_type".to_string(), type_lit_h),
        ("name".to_string(), name_lit_h),
        ("age".to_string(), age_lit_h),
    ];
    let mut budget2 = Budget::default_budget();
    let mut ctx2 = EvalContext::new(&cs, &li, &included, &pid);
    let builtin_result = dispatch_builtin_alias(
        BUILTIN_CONSTRUCT,
        "eval",
        &args,
        &Scope::new(),
        &mut budget2,
        &mut ctx2,
    )
    .expect("dispatch_builtin_alias should recognize builtins/construct");
    let builtin_hash = match builtin_result {
        ComputeValue::Entity(e) => e.content_hash,
        other => panic!("builtin construct didn't return entity: {:?}", other),
    };

    assert_eq!(
        inline_hash, builtin_hash,
        "§3.5 inline-vs-handler equivalence violated: compute/construct inline \
         and system/compute/builtins/construct MUST hash identically"
    );
}

// ---------------------------------------------------------------------------
// v3.19b regression tests — kind-tagged scope bindings (§2.3 N1/N3/N4/N6/N8).
// ---------------------------------------------------------------------------

/// v3.19b N2 cross-impl hash-agreement gate. Mirrors the
/// `v319b_scope_hash_agreement` validate-peer vector landed in core-go
/// (`cmd/internal/validate/compute.go`): captures a fixed-content scope
/// (`Let(n=42, λ_.lookup_scope(n))`) and locks in the resulting
/// `compute/scope` content hash so any future change that breaks bit-identical
/// cross-impl agreement is caught immediately.
///
/// **Expected hash (three-way agreement, Go + Rust + Python):**
/// `ecf-sha256:3edc51381d12e22a22412890d329cbab87d98970362b5a4c1b3e0328effb9efd`.
#[test]
fn test_v319b_n2_scope_hash_three_way_agreement() {
    const EXPECTED: &str =
        "3edc51381d12e22a22412890d329cbab87d98970362b5a4c1b3e0328effb9efd";

    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // n = 42; body = lookup_scope("n"); lambda(_) of body; let(n=42, lambda).
    let lit42_h = cs.put(make_literal_int(42)).unwrap();
    let lookup_n_h = cs.put(make_scope_lookup("n")).unwrap();
    let lambda_h = cs.put(make_lambda(&["_"], lookup_n_h)).unwrap();
    let let_expr = make_let(&[("n", lit42_h)], lambda_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&let_expr, &Scope::new(), &mut budget, &mut ctx);

    let closure = match result {
        ComputeValue::Closure(c) => c,
        other => panic!("expected closure, got {:?}", other),
    };
    let env = closure.env.expect("closure must have captured env");

    let mut got = String::with_capacity(64);
    for b in env.digest().iter() {
        use std::fmt::Write;
        write!(&mut got, "{:02x}", b).unwrap();
    }
    assert_eq!(
        got, EXPECTED,
        "v3.19b N2 scope content hash drift — Rust no longer agrees with the \
         cross-impl hash (Go + Rust + Python). Wire-shape change?"
    );
}

/// v3.19b N3 regression detector (the cross-impl `v319_n5_disambiguation`
/// shape). This is the F9-B-residual scenario: a captured `params`-like entity
/// must round-trip through scope as an entity (not as its envelope's bare
/// CBOR), so `field(scope.captured, "threshold")` navigates `.data.threshold`
/// (entity path), not envelope keys (record path).
///
/// Pre-v3.19b: capture serialized the Entity to bytes-hash → load returned
/// `Primitive(Bytes)` → field on it type-mismatched.
/// v3.19b: capture emits `{kind:"entity", entity_hash}` → load resolves back
/// to `Entity` → field navigates `.data.threshold` and yields the value.
#[test]
fn test_v319b_n3_closure_captures_entity_field_navigation() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Bind an entity at a tree path so a tree-lookup can pull it into scope.
    let params = Entity::new(
        "app/params",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "threshold" => entity_ecf::integer(42)
        }),
    )
    .unwrap();
    let ph = cs.put(params).unwrap();
    li.set(&format!("/{}/app/params", TEST_PID), ph);

    // Build a lambda body: field(lookup/scope("captured"), "threshold").
    let scope_lookup_h = cs.put(make_scope_lookup("captured")).unwrap();
    let body_h = cs.put(make_field("threshold", scope_lookup_h)).unwrap();
    let lambda_h = cs.put(make_lambda(&[], body_h)).unwrap();

    // Outer expression: let captured = tree-lookup("app/params") in apply(lambda).
    let tree_h = cs.put(make_tree_lookup("app/params")).unwrap();
    let apply_h = cs.put(make_apply_closure(lambda_h, &[])).unwrap();
    let let_expr = make_let(&[("captured", tree_h)], apply_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&let_expr, &Scope::new(), &mut budget, &mut ctx);

    match result {
        ComputeValue::Primitive(v) => assert_eq!(v.as_integer().map(i128::from), Some(42_i128)),
        other => panic!(
            "expected captured-entity field-navigation to yield 42, got {:?}",
            other
        ),
    }
}

/// v3.19b N1/N6 round-trip: a primitive binding survives capture → load
/// unchanged. The `kind:"value"` branch is the simpler half of the discriminator.
#[test]
fn test_v319b_n1_closure_captures_primitive_value() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // body: lookup/scope("threshold") — just returns the captured primitive.
    let body_h = cs.put(make_scope_lookup("threshold")).unwrap();
    let lambda_h = cs.put(make_lambda(&[], body_h)).unwrap();
    let lit_h = cs.put(make_literal_int(7)).unwrap();
    let apply_h = cs.put(make_apply_closure(lambda_h, &[])).unwrap();
    let let_expr = make_let(&[("threshold", lit_h)], apply_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&let_expr, &Scope::new(), &mut budget, &mut ctx);

    match result {
        ComputeValue::Primitive(v) => assert_eq!(v.as_integer().map(i128::from), Some(7_i128)),
        other => panic!("expected primitive value round-trip, got {:?}", other),
    }
}

/// v3.19b §3.2 / N6 — `is_error` covers TYPE_ERROR entities. A `compute/error`
/// entity (including one read from a tree path) is recognized as an error
/// regardless of which `ComputeValue` variant holds it. Error short-circuit
/// guards then catch it before truthiness or any other check fires, so the
/// NaN-propagation invariant from §1.5 holds across boundaries.
#[test]
fn test_v319b_is_error_covers_typed_error_entity() {
    use crate::types::ComputeError;
    let err_entity = ComputeError::TypeMismatch("test".into()).to_entity();
    let as_value = ComputeValue::Entity(err_entity);
    assert!(
        as_value.is_error(),
        "ComputeValue::Entity(compute/error) must be is_error()"
    );

    let non_err = Entity::new(
        "app/data",
        entity_ecf::to_ecf(&entity_ecf::cbor_map! { "x" => entity_ecf::integer(1) }),
    )
    .unwrap();
    assert!(
        !ComputeValue::Entity(non_err).is_error(),
        "non-error entity must NOT be is_error()"
    );
}

/// v3.19b N8 — a `kind:"entity"` binding whose hash doesn't resolve aborts
/// the closure apply with `scope_unreachable`, **eagerly** (v3.19b
/// close-out). The body of the closure is never reached, even if it never
/// touches the unresolvable binding — empirical 2/3 + spec text "at apply
/// time" + F9-B intent agree on eager resolution.
///
/// Synthesizes the unreachable case by manually writing a `compute/scope`
/// entity that references a non-existent binding-entity hash, then triggering
/// a closure apply that loads that scope. The closure body returns a constant
/// (`42`) and never references the unreachable binding — eager still fails.
#[test]
fn test_v319b_n8_missing_binding_scope_unreachable() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Forge a scope entity with a `kind:"entity"` binding pointing at a hash
    // we never put into the store.
    let phantom_hash = Hash::compute("app/phantom", b"never-stored");
    let scope_data = entity_ecf::cbor_map! {
        "bindings" => Value::Map(vec![(
            Value::Text("missing".into()),
            Value::Map(vec![
                (Value::Text("kind".into()), Value::Text("entity".into())),
                (Value::Text("entity_hash".into()), Value::Bytes(phantom_hash.to_bytes().to_vec())),
            ]),
        )])
    };
    let scope_entity = Entity::new(TYPE_SCOPE, entity_ecf::to_ecf(&scope_data)).unwrap();
    let scope_hash = cs.put(scope_entity).unwrap();

    // Build a closure entity whose body is a constant 42 — it never touches
    // the unreachable "missing" binding. Eager LoadScope still fails the
    // apply because the binding hash doesn't resolve on entry.
    let body_h = cs.put(make_literal_int(42)).unwrap();
    let closure_data = entity_ecf::cbor_map! {
        "body" => Value::Bytes(body_h.to_bytes().to_vec()),
        "env" => Value::Bytes(scope_hash.to_bytes().to_vec()),
        "params" => Value::Array(vec![])
    };
    let closure_entity = Entity::new(TYPE_CLOSURE, entity_ecf::to_ecf(&closure_data)).unwrap();
    let closure_h = cs.put(closure_entity).unwrap();

    // Apply the closure (no args).
    let apply = make_apply_closure(closure_h, &[]);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid).with_capability(Some(&cap));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);

    match result {
        ComputeValue::Error(ComputeError::ScopeUnreachable(_)) => {}
        other => panic!(
            "expected scope_unreachable for missing binding hash, got {:?}",
            other
        ),
    }
}

// --- Construct tests ---

#[test]
fn test_construct_entity() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let name_lit = make_literal_str("Alice");
    let age_lit = make_literal_int(30);
    let nh = cs.put(name_lit).unwrap();
    let ah = cs.put(age_lit).unwrap();

    let expr = make_construct("app/person", &[("name", nh), ("age", ah)]);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Entity(e) => {
            assert_eq!(e.entity_type, "app/person");
            // v3.19c α: a compute-constructed entity's data is
            // bare per V7 §1.4 — no kind-tags. Same shape as a hand-built
            // entity. The materialized form is the validate-peer gate.
            let data = decode_data(&e).unwrap();
            assert_eq!(data.get("name").and_then(|v| v.as_str()), Some("Alice"));
            assert_eq!(data.get("age").and_then(|v| v.as_i64()), Some(30));
        }
        _ => panic!("expected entity, got {:?}", result),
    }
}

// --- Budget and depth tests ---

#[test]
fn test_budget_exhaustion() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_int(42);
    let (included, pid) = test_ctx();
    let mut budget = Budget::new(0, 100);
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&entity, &Scope::new(), &mut budget, &mut ctx);
    assert!(result.is_error());
    match result {
        ComputeValue::Error(ComputeError::BudgetExhausted) => {}
        _ => panic!("expected BudgetExhausted"),
    }
}

#[test]
fn test_depth_exhaustion() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let entity = make_literal_int(42);
    let (included, pid) = test_ctx();
    let mut budget = Budget::new(100, 0);
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&entity, &Scope::new(), &mut budget, &mut ctx);
    assert!(result.is_error());
    match result {
        ComputeValue::Error(ComputeError::DepthExceeded) => {}
        _ => panic!("expected DepthExceeded"),
    }
}

// --- Error short-circuit ---

#[test]
fn test_error_short_circuit_arithmetic() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // left operand produces an error (div by zero), right should not be evaluated
    let left_l = make_literal_int(1);
    let left_r = make_literal_int(0);
    let llh = cs.put(left_l).unwrap();
    let lrh = cs.put(left_r).unwrap();
    let left_div = make_arithmetic("div", llh, lrh);
    let left_div_h = cs.put(left_div).unwrap();

    let right = make_literal_int(5);
    let rh = cs.put(right).unwrap();

    let expr = make_arithmetic("add", left_div_h, rh);
    let result = eval_entity(&cs, &li, &expr);
    assert!(result.is_error());
}

// --- Truthiness tests ---

#[test]
fn test_truthiness() {
    assert!(ComputeValue::Primitive(entity_ecf::integer(1)).is_truthy());
    assert!(!ComputeValue::Primitive(entity_ecf::integer(0)).is_truthy());
    assert!(!ComputeValue::Primitive(Value::Null).is_truthy());
    assert!(!ComputeValue::Primitive(Value::Bool(false)).is_truthy());
    assert!(ComputeValue::Primitive(Value::Bool(true)).is_truthy());
    assert!(!ComputeValue::Primitive(Value::Text(String::new())).is_truthy());
    assert!(ComputeValue::Primitive(Value::Text("x".into())).is_truthy());
    assert!(!ComputeValue::Primitive(Value::Array(vec![])).is_truthy());
    assert!(ComputeValue::Primitive(Value::Array(vec![Value::Null])).is_truthy());
}

// --- Canonical ordering test ---

#[test]
fn test_canonical_sorted() {
    let h1 = Hash::compute("a", b"1");
    let h2 = Hash::compute("b", b"2");
    let h3 = Hash::compute("cc", b"3");

    let pairs = vec![
        ("cc".to_string(), h3),
        ("a".to_string(), h1),
        ("b".to_string(), h2),
    ];
    let sorted = canonical_sorted_pairs(&pairs);
    // "a" and "b" have same encoded length (1 char), sorted alphabetically
    // "cc" has longer encoded length (2 chars), comes last
    assert_eq!(sorted[0].0, "a");
    assert_eq!(sorted[1].0, "b");
    assert_eq!(sorted[2].0, "cc");
}

// --- v3.7 compute/lookup/hash tests ---

#[test]
fn test_lookup_hash_compute_entity() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Store a compute expression in content store
    let lit = make_literal_int(99);
    let lit_h = cs.put(lit).unwrap();

    // lookup/hash resolves compute entities via Tier 1 (compute type)
    let lookup = make_hash_lookup(lit_h, None);
    let result = eval_entity(&cs, &li, &lookup);
    assert_eq!(result.as_i128(), Some(99));
}

#[test]
fn test_lookup_hash_noncompute_rejected_without_seal() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Store a non-compute entity
    let data_entity = Entity::new("app/data", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "x" => entity_ecf::integer(42)
    })).unwrap();
    let dh = cs.put(data_entity).unwrap();

    // Without authorized_data_hashes, non-compute entity rejected (D2)
    let lookup = make_hash_lookup(dh, Some("app/data/item"));
    let result = eval_entity(&cs, &li, &lookup);
    assert!(result.is_error());
}

#[test]
fn test_lookup_hash_noncompute_authorized_via_sealed_set() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Store a non-compute entity
    let data_entity = Entity::new("app/data", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
        "x" => entity_ecf::integer(42)
    })).unwrap();
    let dh = cs.put(data_entity).unwrap();

    // With authorized_data_hashes (sealed set from install), it resolves
    let lookup = make_hash_lookup(dh, Some("app/data/item"));
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut authorized = HashSet::new();
    authorized.insert(dh);
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_authorized_hashes(authorized);
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Entity(e) => assert_eq!(e.entity_type, "app/data"),
        _ => panic!("expected entity, got {:?}", result),
    }
}

// --- v3.6 cross-implementation test vectors (§8.4) ---

fn make_literal_float(f: f64) -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => Value::Float(f)
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn arith(cs: &dyn ContentStore, li: &dyn LocationIndex, op: &str, l: Entity, r: Entity) -> ComputeValue {
    let lh = cs.put(l).unwrap();
    let rh = cs.put(r).unwrap();
    let expr = make_arithmetic(op, lh, rh);
    eval_entity(cs, li, &expr)
}

fn cmp(cs: &dyn ContentStore, li: &dyn LocationIndex, op: &str, l: Entity, r: Entity) -> ComputeValue {
    let lh = cs.put(l).unwrap();
    let rh = cs.put(r).unwrap();
    let expr = make_compare(op, lh, rh);
    eval_entity(cs, li, &expr)
}

#[test]
fn test_v36_div_exact_integer() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "div", make_literal_int(10), make_literal_int(2));
    assert_eq!(r.as_i128(), Some(5));
}

#[test]
fn test_v36_div_nonexact_float() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "div", make_literal_int(7), make_literal_int(2));
    assert_eq!(r.as_f64(), Some(3.5));
}

#[test]
fn test_v36_div_negative_float() {
    // v3.16 rule 9: div is signed-default → no casts needed. Restores the
    // bare-operand form the spec's §276 examples assume (per rule 4 note
    // "operands interpreted signed per rule 9 — these examples evaluate as
    // written, no casts").
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "div", make_literal_int(-7), make_literal_int(2));
    assert_eq!(r.as_f64(), Some(-3.5));
}

#[test]
fn test_v36_mod_truncated() {
    // v3.16 rule 4: signed mod with truncated remainder; rule 9: signed-default.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    assert_eq!(arith(&cs, &li, "mod", make_literal_int(7), make_literal_int(3)).as_i128(), Some(1));
    assert_eq!(arith(&cs, &li, "mod", make_literal_int(-7), make_literal_int(3)).as_i128(), Some(-1));
    assert_eq!(arith(&cs, &li, "mod", make_literal_int(7), make_literal_int(-3)).as_i128(), Some(1));
    assert_eq!(arith(&cs, &li, "mod", make_literal_int(-7), make_literal_int(-3)).as_i128(), Some(-1));
}

#[test]
fn test_v36_mixed_type_promotion() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "add", make_literal_int(1), make_literal_float(2.5));
    assert_eq!(r.as_f64(), Some(3.5));
}

#[test]
fn test_v36_float_mul() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "mul", make_literal_int(3), make_literal_float(2.0));
    assert_eq!(r.as_f64(), Some(6.0));
}

#[test]
fn test_v36_float_div_by_zero_inf() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "div", make_literal_float(1.0), make_literal_float(0.0));
    assert_eq!(r.as_f64(), Some(f64::INFINITY));
}

#[test]
fn test_v36_float_div_by_zero_nan() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = arith(&cs, &li, "div", make_literal_float(0.0), make_literal_float(0.0));
    assert!(r.as_f64().map(|f| f.is_nan()).unwrap_or(false));
}

#[test]
fn test_v36_eq_cross_type_numeric() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    match cmp(&cs, &li, "eq", make_literal_int(1), make_literal_float(1.0)) {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        other => panic!("expected true, got {:?}", other),
    }
}

#[test]
fn test_v36_eq_incompatible_types() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    match cmp(&cs, &li, "eq", make_literal_int(1), make_literal_str("1")) {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(!b),
        other => panic!("expected false, got {:?}", other),
    }
}

#[test]
fn test_v36_string_comparison() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    match cmp(&cs, &li, "lt", make_literal_str("abc"), make_literal_str("abd")) {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        other => panic!("expected true, got {:?}", other),
    }
}

#[test]
fn test_v36_lt_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let r = cmp(&cs, &li, "lt", make_literal_int(1), make_literal_str("abc"));
    assert!(r.is_error());
}

// --- v3.8 TCO tests (T1-T3) ---

/// Build a self-recursive closure. The closure takes "self" as its first parameter
/// so it can call itself. Returns (closure_entity_hash, lookup_self_hash) where
/// lookup_self_hash resolves to `compute/lookup/scope{name: "self"}` for the
/// recursive apply's fn field.
fn build_tail_recursive_counter(cs: &dyn ContentStore) -> (Hash, Hash) {
    // lambda(self, n, acc) -> if (n <= 0) then acc else apply(self, {self, n-1, acc+1})
    let lit_0 = make_literal_int(0);
    let lit_0h = cs.put(lit_0).unwrap();
    let lit_1 = make_literal_int(1);
    let lit_1h = cs.put(lit_1).unwrap();

    let lookup_self = make_scope_lookup("self");
    let lookup_selfh = cs.put(lookup_self).unwrap();
    let lookup_n = make_scope_lookup("n");
    let lookup_nh = cs.put(lookup_n).unwrap();
    let lookup_acc = make_scope_lookup("acc");
    let lookup_acch = cs.put(lookup_acc).unwrap();

    let cond = make_compare("lte", lookup_nh, lit_0h);
    let condh = cs.put(cond).unwrap();

    let n_minus_1 = make_arithmetic("sub", lookup_nh, lit_1h);
    let n_minus_1h = cs.put(n_minus_1).unwrap();

    let acc_plus_1 = make_arithmetic("add", lookup_acch, lit_1h);
    let acc_plus_1h = cs.put(acc_plus_1).unwrap();

    // Tail-recursive call: apply(self, {self: self, n: n-1, acc: acc+1})
    let recurse = make_apply_closure(
        lookup_selfh,
        &[("acc", acc_plus_1h), ("n", n_minus_1h), ("self", lookup_selfh)],
    );
    let recurseh = cs.put(recurse).unwrap();

    let if_expr = make_if(condh, lookup_acch, Some(recurseh));
    let if_h = cs.put(if_expr).unwrap();

    let body_lambda = make_lambda(&["self", "n", "acc"], if_h);
    let lambda_h = cs.put(body_lambda).unwrap();

    (lambda_h, lookup_selfh)
}

#[test]
fn test_tco_tail_recursive_iteration() {
    // count_down(self, n, acc) = if n<=0 then acc else count_down(self, n-1, acc+1)
    // With TCO, n=2000 succeeds despite depth limit of 1024.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let (lambda_h, _) = build_tail_recursive_counter(&cs);

    // Evaluate lambda to get closure entity
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let lambda_entity = cs.get(&lambda_h).unwrap();
    let closure_val = evaluate(&lambda_entity, &Scope::new(), &mut budget, &mut ctx);
    let closure = match &closure_val {
        ComputeValue::Closure(c) => c.clone(),
        _ => panic!("expected closure"),
    };
    let closure_entity = closure.to_entity();
    let closure_hash = cs.put(closure_entity).unwrap();

    // Initial call: apply(closure, {self: closure, n: 2000, acc: 0})
    let lit_0 = make_literal_int(0);
    let lit_0h = cs.put(lit_0).unwrap();
    let lit_2000 = make_literal_int(2000);
    let lit_2000h = cs.put(lit_2000).unwrap();

    // Hash lookup for closure so it can be passed as arg value
    let closure_lookup = make_hash_lookup(closure_hash, None);
    let closure_lookup_h = cs.put(closure_lookup).unwrap();

    let call = make_apply_closure(
        closure_hash,
        &[("acc", lit_0h), ("n", lit_2000h), ("self", closure_lookup_h)],
    );

    let mut budget2 = Budget::new(200_000, 1_024);
    let mut ctx2 = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&call, &Scope::new(), &mut budget2, &mut ctx2);

    assert_eq!(result.as_i128(), Some(2000));
    assert!(budget2.depth > 0);
}

/// Microbench mirroring the validator's `v38_tco_if_chain` shape — 1100 nested
/// `if(true, then=next)` levels — to measure pure TCO eval cost (puts excluded).
/// `#[ignore]`d; run with
/// `cargo test -p entity-compute --release perf_tco_if_chain_eval -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_tco_if_chain_eval() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let cond = make_literal_bool(true);
    let cond_h = cs.put(cond).unwrap();
    let final_lit = make_literal_int(42);
    let mut current_h = cs.put(final_lit).unwrap();
    for _ in 0..1100 {
        let if_e = make_if(cond_h, current_h, None);
        current_h = cs.put(if_e).unwrap();
    }
    let outer = make_if(cond_h, current_h, None);

    let (included, pid) = test_ctx();
    let mut budget = Budget::new(200_000, 1_024);
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);

    let start = web_time::Instant::now();
    let result = evaluate(&outer, &Scope::new(), &mut budget, &mut ctx);
    let elapsed = start.elapsed();

    assert_eq!(result.as_i128(), Some(42));
    eprintln!("perf_tco_if_chain_eval: 1101-deep if-chain in {:?}", elapsed);
}

/// Same shape but `let(_=lit, body=next)` — let-chain test mirror. Each
/// iteration grows the scope by one binding, so this exercises scope cloning
/// per tail call.
#[test]
#[ignore]
fn perf_tco_let_chain_eval() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let lit = make_literal_int(1);
    let lit_h = cs.put(lit).unwrap();
    let final_lit = make_literal_int(99);
    let mut current_h = cs.put(final_lit).unwrap();
    for _ in 0..1100 {
        let let_e = make_let(&[("_", lit_h)], current_h);
        current_h = cs.put(let_e).unwrap();
    }
    let outer = make_let(&[("_", lit_h)], current_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::new(200_000, 1_024);
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);

    let start = web_time::Instant::now();
    let result = evaluate(&outer, &Scope::new(), &mut budget, &mut ctx);
    let elapsed = start.elapsed();

    assert_eq!(result.as_i128(), Some(99));
    eprintln!("perf_tco_let_chain_eval: 1101-deep let-chain in {:?}", elapsed);
}

#[test]
fn test_tco_non_tail_recursion_still_bounded() {
    // f(self, n) = if n<=0 then 0 else f(self, n-1) + 1
    // The add wraps the recursive call, so it's NOT a tail position.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let lit_0 = make_literal_int(0);
    let lit_0h = cs.put(lit_0).unwrap();
    let lit_1 = make_literal_int(1);
    let lit_1h = cs.put(lit_1).unwrap();

    let lookup_self = make_scope_lookup("self");
    let lookup_selfh = cs.put(lookup_self).unwrap();
    let lookup_n = make_scope_lookup("n");
    let lookup_nh = cs.put(lookup_n).unwrap();

    let cond = make_compare("lte", lookup_nh, lit_0h);
    let condh = cs.put(cond).unwrap();

    let n_minus_1 = make_arithmetic("sub", lookup_nh, lit_1h);
    let n_minus_1h = cs.put(n_minus_1).unwrap();

    // Non-tail: apply(self, {self, n-1}) is inside add, not in tail position
    let recurse = make_apply_closure(
        lookup_selfh,
        &[("n", n_minus_1h), ("self", lookup_selfh)],
    );
    let recurseh = cs.put(recurse).unwrap();

    let add_expr = make_arithmetic("add", recurseh, lit_1h);
    let add_h = cs.put(add_expr).unwrap();

    let if_expr = make_if(condh, lit_0h, Some(add_h));
    let if_h = cs.put(if_expr).unwrap();

    let body_lambda = make_lambda(&["self", "n"], if_h);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let closure_val = evaluate(&body_lambda, &Scope::new(), &mut budget, &mut ctx);
    let closure = match &closure_val {
        ComputeValue::Closure(c) => c.clone(),
        _ => panic!("expected closure"),
    };
    let closure_entity = closure.to_entity();
    let closure_hash = cs.put(closure_entity).unwrap();

    let lit_2000 = make_literal_int(2000);
    let lit_2000h = cs.put(lit_2000).unwrap();

    let closure_lookup = make_hash_lookup(closure_hash, None);
    let closure_lookup_h = cs.put(closure_lookup).unwrap();

    let call = make_apply_closure(
        closure_hash,
        &[("n", lit_2000h), ("self", closure_lookup_h)],
    );

    let mut budget2 = Budget::new(200_000, 1_024);
    let mut ctx2 = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&call, &Scope::new(), &mut budget2, &mut ctx2);

    assert!(result.is_error());
    match result {
        ComputeValue::Error(ComputeError::DepthExceeded) => {}
        other => panic!("expected DepthExceeded, got {:?}", other),
    }
}

#[test]
fn test_tco_budget_still_decrements() {
    // Same tail-recursive counter, but with tiny budget — should exhaust operations.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let (lambda_h, _) = build_tail_recursive_counter(&cs);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let lambda_entity = cs.get(&lambda_h).unwrap();
    let closure_val = evaluate(&lambda_entity, &Scope::new(), &mut budget, &mut ctx);
    let closure = match &closure_val {
        ComputeValue::Closure(c) => c.clone(),
        _ => panic!("expected closure"),
    };
    let closure_entity = closure.to_entity();
    let closure_hash = cs.put(closure_entity).unwrap();

    let lit_0 = make_literal_int(0);
    let lit_0h = cs.put(lit_0).unwrap();
    let lit_big = make_literal_int(100_000);
    let lit_bigh = cs.put(lit_big).unwrap();

    let closure_lookup = make_hash_lookup(closure_hash, None);
    let closure_lookup_h = cs.put(closure_lookup).unwrap();

    let call = make_apply_closure(
        closure_hash,
        &[("acc", lit_0h), ("n", lit_bigh), ("self", closure_lookup_h)],
    );

    let mut budget2 = Budget::new(50, 1_024);
    let mut ctx2 = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&call, &Scope::new(), &mut budget2, &mut ctx2);

    assert!(result.is_error());
    match result {
        ComputeValue::Error(ComputeError::BudgetExhausted) => {}
        other => panic!("expected BudgetExhausted, got {:?}", other),
    }
}

// --- v3.8 Relative path tests (R1-R2) ---

fn make_tree_lookup_relative(path: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "path" => entity_ecf::text(path),
        "relative" => Value::Bool(true)
    };
    Entity::new(TYPE_LOOKUP_TREE, entity_ecf::to_ecf(&data)).unwrap()
}

#[test]
fn test_relative_tree_lookup() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    // Store data at app/compute/job1/data/input
    let stored = make_literal_int(42);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/app/compute/job1/data/input", pid), hash);

    // Relative lookup: path="data/input", relative=true, root="app/compute/job1"
    let lookup = make_tree_lookup_relative("data/input");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid)
        .with_capability(Some(&cap))
        .with_subgraph_root(Some("app/compute/job1".to_string()));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(42));
}

#[test]
fn test_relative_tree_lookup_dependency_tracking() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    let stored = make_literal_int(1);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/root/data/x", pid), hash);

    let lookup = make_tree_lookup_relative("data/x");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid)
        .with_capability(Some(&cap))
        .with_subgraph_root(Some("root".to_string()));
    ctx.dependency_paths = Some(Vec::new());
    let _ = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);

    // Dependency should be recorded as the resolved absolute path
    let deps = ctx.dependency_paths.unwrap();
    assert_eq!(deps, vec!["root/data/x"]);
}

#[test]
fn test_absolute_tree_lookup_unchanged() {
    // Without relative=true, paths resolve as before
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    let stored = make_literal_int(99);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/app/data/x", pid), hash);

    let lookup = make_tree_lookup("app/data/x");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid)
        .with_capability(Some(&cap))
        .with_subgraph_root(Some("some/other/root".to_string()));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(99));
}

#[test]
fn test_resolve_relative_path_helper() {
    assert_eq!(
        resolve_relative_path(Some("app/root"), "data/x"),
        "app/root/data/x"
    );
    assert_eq!(
        resolve_relative_path(Some("app/root/"), "data/x"),
        "app/root/data/x"
    );
    assert_eq!(
        resolve_relative_path(Some("app/root"), "/data/x"),
        "app/root/data/x"
    );
    assert_eq!(
        resolve_relative_path(None, "data/x"),
        "data/x"
    );
}

// --- §7.2 capability check tests ---

/// Build a capability with a single grant: tree GET on the given path scope.
fn cap_with_tree_read(scope: Vec<&str>) -> entity_capability::CapabilityToken {
    entity_capability::CapabilityToken {
        grants: vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(
                scope.into_iter().map(String::from).collect(),
            ),
            operations: entity_capability::IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: entity_capability::Granter::Single(Hash::compute("test", b"granter")),
        grantee: Hash::compute("test", b"grantee"),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

#[test]
fn test_lookup_tree_no_capability_denies() {
    // §7.2: missing ctx.capability MUST fail-closed for tree reads.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    let stored = make_literal_int(42);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/app/cell/A1", pid), hash);

    let lookup = make_tree_lookup("app/cell/A1");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid);
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Error(ComputeError::PermissionDenied(_)) => {}
        other => panic!("expected PermissionDenied, got {:?}", other),
    }
}

#[test]
fn test_lookup_tree_capability_out_of_scope_denies() {
    // §7.2: ctx.capability that doesn't cover the resource MUST deny the read.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    let stored = make_literal_int(7);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/system/secret/admin", pid), hash);

    let lookup = make_tree_lookup("system/secret/admin");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    // Cap covers app/* only, not system/secret/*.
    let cap = cap_with_tree_read(vec!["app/*"]);
    let mut ctx = EvalContext::new(&cs, &li, &included, pid).with_capability(Some(&cap));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Error(ComputeError::PermissionDenied(_)) => {}
        other => panic!("expected PermissionDenied, got {:?}", other),
    }
}

#[test]
fn test_lookup_tree_capability_in_scope_allows() {
    // §7.2: ctx.capability that covers the resource permits the read.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    let stored = make_literal_int(123);
    let hash = cs.put(stored).unwrap();
    li.set(&format!("/{}/app/data/x", pid), hash);

    let lookup = make_tree_lookup("app/data/x");
    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();
    let cap = cap_with_tree_read(vec!["app/*"]);
    let mut ctx = EvalContext::new(&cs, &li, &included, pid).with_capability(Some(&cap));
    let result = evaluate(&lookup, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(123));
}

// --- Handler dispatch tests ---

fn make_apply_handler(path: &str, operation: &str, args: &[(&str, Hash)]) -> Entity {
    let args_map: Vec<(Value, Value)> = args
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let mut fields = vec![
        (Value::Text("args".into()), Value::Map(args_map)),
        (Value::Text("operation".into()), entity_ecf::text(operation)),
        (Value::Text("path".into()), entity_ecf::text(path)),
    ];
    fields.sort_by(|(a, _), (b, _)| {
        let a_bytes = entity_ecf::to_ecf(a);
        let b_bytes = entity_ecf::to_ecf(b);
        a_bytes.len().cmp(&b_bytes.len()).then(a_bytes.cmp(&b_bytes))
    });
    Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&Value::Map(fields))).unwrap()
}

#[test]
fn test_handler_dispatch_with_callback() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    // Build: apply(path="system/compute", operation="eval", args={expression_uri: literal("test")})
    let uri_lit = make_literal_str("test/path");
    let uri_h = cs.put(uri_lit).unwrap();
    let apply = make_apply_handler("system/compute", "eval", &[("expression_uri", uri_h)]);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();

    // Wire a mock dispatch that returns the params as confirmation
    let dispatch: TestDispatchFn = Box::new(|path, operation, _resource, params, _cap_override| {
        assert_eq!(path, "system/compute");
        assert_eq!(operation, "eval");
        let data = decode_data(&params).unwrap();
        let uri = data_str(&data, "expression_uri").unwrap();
        assert_eq!(uri, "test/path");
        ComputeValue::Primitive(entity_ecf::integer(42))
    });

    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_dispatch_execute(Some(dispatch));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(42));
}

#[test]
fn test_handler_dispatch_without_callback() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let uri_lit = make_literal_str("test/path");
    let uri_h = cs.put(uri_lit).unwrap();
    let apply = make_apply_handler("system/compute", "eval", &[("expression_uri", uri_h)]);

    let result = eval_entity(&cs, &li, &apply);
    assert!(result.is_error());
}

// --- §3.2 dual-check tests ---

/// Build compute/apply with optional `capability` and `resource` fields.
///
/// When `capability` is set, F5 requires `resource` to also be set — callers
/// pass `Some(resource_hash)` to satisfy that. Pass `None` to omit the
/// resource field (e.g., when testing the F5 violation itself).
fn make_apply_handler_with_cap(
    path: &str,
    operation: &str,
    args: &[(&str, Hash)],
    capability: Hash,
    resource: Option<Hash>,
) -> Entity {
    let args_map: Vec<(Value, Value)> = args
        .iter()
        .map(|(name, hash)| {
            (
                Value::Text(name.to_string()),
                Value::Bytes(hash.to_bytes().to_vec()),
            )
        })
        .collect();
    let mut fields = vec![
        (Value::Text("args".into()), Value::Map(args_map)),
        (
            Value::Text("capability".into()),
            Value::Bytes(capability.to_bytes().to_vec()),
        ),
        (Value::Text("operation".into()), entity_ecf::text(operation)),
        (Value::Text("path".into()), entity_ecf::text(path)),
    ];
    if let Some(rh) = resource {
        fields.push((
            Value::Text("resource".into()),
            Value::Bytes(rh.to_bytes().to_vec()),
        ));
    }
    fields.sort_by(|(a, _), (b, _)| {
        let a_bytes = entity_ecf::to_ecf(a);
        let b_bytes = entity_ecf::to_ecf(b);
        a_bytes.len().cmp(&b_bytes.len()).then(a_bytes.cmp(&b_bytes))
    });
    Entity::new(TYPE_APPLY, entity_ecf::to_ecf(&Value::Map(fields))).unwrap()
}

/// Build a compute/literal entity whose value is a system/protocol/resource-target
/// shaped map: `{targets: [...], exclude: [...]}`. Used to back compute/apply's
/// `resource` field with a static literal expression.
fn make_resource_literal(targets: &[&str], exclude: &[&str]) -> Entity {
    let value = Value::Map(vec![
        (
            Value::Text("exclude".into()),
            Value::Array(exclude.iter().map(|s| entity_ecf::text(*s)).collect()),
        ),
        (
            Value::Text("targets".into()),
            Value::Array(targets.iter().map(|s| entity_ecf::text(*s)).collect()),
        ),
    ]);
    let data = entity_ecf::cbor_map! {
        "value" => value
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

/// Build a placeholder capability entity (cosmetic; resolution targets it by hash).
fn make_capability_token_entity(label: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "label" => entity_ecf::text(label)
    };
    Entity::new("system/capability/token", entity_ecf::to_ecf(&data)).unwrap()
}

#[test]
fn test_apply_capability_field_dual_check_denies_outside_handler_grant() {
    // Handler grant covers system/tree:get on app/foo/* only. Caller's provided
    // cap is admin (covers everything). The expression targets system/secret/x
    // — the F2 full-resolution dual-check (v3.10) MUST fail because the handler
    // grant does not cover that resource, even though the override cap does.
    // This is row 3 of the proposal's §5 test vectors — the security test.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let admin_cap = make_capability_token_entity("admin");
    let admin_cap_h = cs.put(admin_cap.clone()).unwrap();
    // Cap is a non-compute entity — authorize via sealed set (Tier 2 / §4.2).
    let mut authorized = HashSet::new();
    authorized.insert(admin_cap_h);

    // Resource literal targeting system/secret/x — outside handler grant scope.
    let resource_lit = make_resource_literal(&["system/secret/x"], &[]);
    let resource_h = cs.put(resource_lit).unwrap();
    let included: HashMap<Hash, Entity> = HashMap::new();

    let apply = make_apply_handler_with_cap(
        "system/tree",
        "get",
        &[],
        admin_cap_h,
        Some(resource_h),
    );

    let pid = TEST_PID.to_string();
    let mut budget = Budget::default_budget();

    // Handler grant covers system/tree:get on app/foo/* only — does NOT cover
    // system/secret/*. Even with a broader provided cap, F2 full-resolution
    // dual-check denies because the handler grant ceiling binds at the resource
    // level (the v3.10 fix — pre-fix, resource was passed null and the check
    // would silently pass).
    let handler_grant = entity_capability::CapabilityToken {
        grants: vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(vec!["app/foo/*".into()]),
            operations: entity_capability::IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: entity_capability::Granter::Single(Hash::compute("test", b"granter")),
        grantee: Hash::compute("test", b"grantee"),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let dispatch: TestDispatchFn = Box::new(|_, _, _, _, _| ComputeValue::Primitive(entity_ecf::integer(0)));

    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_capability(Some(&handler_grant))
        .with_authorized_hashes(authorized)
        .with_dispatch_execute(Some(dispatch));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Error(ComputeError::PermissionDenied(msg)) => {
            assert!(msg.contains("Handler grant does not cover target"), "{}", msg);
        }
        other => panic!("expected PermissionDenied, got {:?}", other),
    }
}

#[test]
fn test_apply_capability_field_dual_check_passes_within_handler_grant() {
    // Handler grant covers system/tree:get; provided cap also covers it.
    // Dual-check passes — dispatch is invoked with the override cap, and the
    // resolved resource flows through to the dispatch closure (F4).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let provided_cap = make_capability_token_entity("provided");
    let provided_cap_h = cs.put(provided_cap.clone()).unwrap();
    let mut authorized = HashSet::new();
    authorized.insert(provided_cap_h);

    let resource_lit = make_resource_literal(&["app/foo/x"], &[]);
    let resource_h = cs.put(resource_lit).unwrap();
    let included: HashMap<Hash, Entity> = HashMap::new();

    let apply = make_apply_handler_with_cap(
        "system/tree",
        "get",
        &[],
        provided_cap_h,
        Some(resource_h),
    );

    let pid = TEST_PID.to_string();
    let mut budget = Budget::default_budget();

    let handler_grant = wildcard_test_cap();

    let saw_override = std::sync::Arc::new(std::sync::Mutex::new(None::<Entity>));
    let saw_resource = std::sync::Arc::new(std::sync::Mutex::new(
        None::<entity_capability::ResourceTarget>,
    ));
    let saw_override_clone = std::sync::Arc::clone(&saw_override);
    let saw_resource_clone = std::sync::Arc::clone(&saw_resource);
    let dispatch: TestDispatchFn = Box::new(move |_path, _op, resource, _params, cap_override| {
        *saw_override_clone.lock().unwrap() = cap_override.clone();
        *saw_resource_clone.lock().unwrap() = resource.clone();
        ComputeValue::Primitive(entity_ecf::integer(99))
    });

    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_capability(Some(&handler_grant))
        .with_authorized_hashes(authorized)
        .with_dispatch_execute(Some(dispatch));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(99));

    let captured = saw_override.lock().unwrap().clone();
    let captured = captured.expect("dispatch should receive cap override");
    assert_eq!(captured.entity_type, "system/capability/token");

    let captured_resource = saw_resource.lock().unwrap().clone();
    let rt = captured_resource.expect("dispatch should receive resolved resource");
    assert_eq!(rt.targets, vec!["app/foo/x".to_string()]);
    assert!(rt.exclude.is_empty());
}

#[test]
fn test_apply_capability_field_without_resource_is_invalid() {
    // F5 (v3.10): compute/apply with `capability` MUST also have `resource`.
    // Without the resource the F2 dual-check would see null at the resource
    // dimension and silently pass — that's the bug. Reject at eval time.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let cap = make_capability_token_entity("any");
    let cap_h = cs.put(cap).unwrap();
    let mut authorized = HashSet::new();
    authorized.insert(cap_h);
    let included: HashMap<Hash, Entity> = HashMap::new();

    // No resource hash — capability without resource is the F5 violation.
    let apply = make_apply_handler_with_cap("system/tree", "get", &[], cap_h, None);

    let pid = TEST_PID.to_string();
    let mut budget = Budget::default_budget();
    let handler_grant = wildcard_test_cap();

    let dispatch: TestDispatchFn = Box::new(|_, _, _, _, _| ComputeValue::Primitive(entity_ecf::integer(0)));

    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_capability(Some(&handler_grant))
        .with_authorized_hashes(authorized)
        .with_dispatch_execute(Some(dispatch));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);
    match result {
        ComputeValue::Error(ComputeError::InvalidExpression(msg)) => {
            assert!(msg.contains("MUST also have resource"), "{}", msg);
        }
        other => panic!("expected InvalidExpression, got {:?}", other),
    }
}

// --- §4.1 input_type assembly tests ---

#[test]
fn test_apply_params_entity_uses_handler_input_type() {
    // §4.1 / §2.1: when the handler manifest declares an input_type for the
    // operation, the params entity dispatched via compute/apply MUST carry
    // that type — not a generic primitive/map.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let pid = TEST_PID;

    // Set up handler at app/echo with interface that declares
    // operations.run.input_type = "app/echo/run-request".
    let interface_data = entity_ecf::cbor_map! {
        "name" => entity_ecf::text("echo"),
        "operations" => Value::Map(vec![
            (entity_ecf::text("run"), Value::Map(vec![
                (entity_ecf::text("input_type"), entity_ecf::text("app/echo/run-request")),
            ])),
        ]),
        "pattern" => entity_ecf::text("app/echo")
    };
    let interface = Entity::new("system/handler/interface", entity_ecf::to_ecf(&interface_data)).unwrap();
    let interface_h = cs.put(interface).unwrap();
    li.set(&format!("/{}/system/handler/app/echo", pid), interface_h);

    let handler_data = entity_ecf::cbor_map! {
        "interface" => entity_ecf::text("system/handler/app/echo")
    };
    let handler = Entity::new("system/handler", entity_ecf::to_ecf(&handler_data)).unwrap();
    let handler_h = cs.put(handler).unwrap();
    li.set(&format!("/{}/app/echo", pid), handler_h);

    let msg = make_literal_str("hi");
    let msg_h = cs.put(msg).unwrap();
    let apply = make_apply_handler("app/echo", "run", &[("message", msg_h)]);

    let (included, _) = test_ctx();
    let mut budget = Budget::default_budget();

    let saw_type = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let saw_type_clone = std::sync::Arc::clone(&saw_type);
    let dispatch: TestDispatchFn = Box::new(move |_path, _op, _resource, params, _cap| {
        *saw_type_clone.lock().unwrap() = params.entity_type.clone();
        ComputeValue::Primitive(entity_ecf::integer(0))
    });

    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, pid)
        .with_capability(Some(&cap))
        .with_dispatch_execute(Some(dispatch));
    let _ = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);

    let captured = saw_type.lock().unwrap().clone();
    assert_eq!(captured, "app/echo/run-request");
}

#[test]
fn test_apply_params_entity_falls_back_to_primitive_map() {
    // When no handler manifest is available (no entity at the dispatch path),
    // params entity falls back to primitive/map per spec's no-type-extension path.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let apply = make_apply_handler("app/no-such-handler", "run", &[]);

    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();

    let saw_type = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let saw_type_clone = std::sync::Arc::clone(&saw_type);
    let dispatch: TestDispatchFn = Box::new(move |_path, _op, _resource, params, _cap| {
        *saw_type_clone.lock().unwrap() = params.entity_type.clone();
        ComputeValue::Primitive(entity_ecf::integer(0))
    });

    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_capability(Some(&cap))
        .with_dispatch_execute(Some(dispatch));
    let _ = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);

    let captured = saw_type.lock().unwrap().clone();
    assert_eq!(captured, "primitive/map");
}

#[test]
fn test_apply_no_capability_field_uses_default() {
    // Without the `capability` field, dispatch is invoked with cap_override=None.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let apply = make_apply_handler("system/tree", "get", &[]);
    let (included, pid) = test_ctx();
    let mut budget = Budget::default_budget();

    let saw_override = std::sync::Arc::new(std::sync::Mutex::new(Some(make_capability_token_entity("sentinel"))));
    let saw_override_clone = std::sync::Arc::clone(&saw_override);
    let dispatch: TestDispatchFn = Box::new(move |_path, _op, _resource, _params, cap_override| {
        *saw_override_clone.lock().unwrap() = cap_override.clone();
        ComputeValue::Primitive(entity_ecf::integer(1))
    });

    let cap = wildcard_test_cap();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid)
        .with_capability(Some(&cap))
        .with_dispatch_execute(Some(dispatch));
    let result = evaluate(&apply, &Scope::new(), &mut budget, &mut ctx);
    assert_eq!(result.as_i128(), Some(1));
    assert!(saw_override.lock().unwrap().is_none(), "no override expected");
}

// =====================================================================
// N.1 — compute/index and compute/length (§2.2)
// =====================================================================

fn make_literal_array(items: Vec<Value>) -> Entity {
    let data = entity_ecf::cbor_map! {
        "value" => Value::Array(items)
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_index(array_hash: Hash, index_hash: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "array" => Value::Bytes(array_hash.to_bytes().to_vec()),
        "index" => Value::Bytes(index_hash.to_bytes().to_vec())
    };
    Entity::new(TYPE_INDEX, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_length(array_hash: Hash) -> Entity {
    let data = entity_ecf::cbor_map! {
        "array" => Value::Bytes(array_hash.to_bytes().to_vec())
    };
    Entity::new(TYPE_LENGTH, entity_ecf::to_ecf(&data)).unwrap()
}

#[test]
fn test_index_basic() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![
        entity_ecf::integer(10),
        entity_ecf::integer(20),
        entity_ecf::integer(30),
    ]);
    let arr_h = cs.put(arr).unwrap();
    let idx = make_literal_int(1);
    let idx_h = cs.put(idx).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    assert_eq!(r.as_i128(), Some(20));
}

#[test]
fn test_index_zero() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![entity_ecf::integer(42)]);
    let arr_h = cs.put(arr).unwrap();
    let idx = make_literal_int(0);
    let idx_h = cs.put(idx).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    assert_eq!(r.as_i128(), Some(42));
}

#[test]
fn test_index_out_of_range_high() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![entity_ecf::integer(1), entity_ecf::integer(2)]);
    let arr_h = cs.put(arr).unwrap();
    let idx = make_literal_int(5);
    let idx_h = cs.put(idx).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    match r {
        ComputeValue::Error(ComputeError::IndexOutOfRange(_)) => {}
        other => panic!("expected IndexOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_index_negative_is_out_of_range() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![entity_ecf::integer(1), entity_ecf::integer(2)]);
    let arr_h = cs.put(arr).unwrap();
    let idx = make_literal_int(-1);
    let idx_h = cs.put(idx).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    match r {
        ComputeValue::Error(ComputeError::IndexOutOfRange(_)) => {}
        other => panic!("expected IndexOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_index_on_null_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr_h = cs.put(make_literal_null()).unwrap();
    let idx_h = cs.put(make_literal_int(0)).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    match r {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

#[test]
fn test_index_on_non_array_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr_h = cs.put(make_literal_str("not an array")).unwrap();
    let idx_h = cs.put(make_literal_int(0)).unwrap();
    let expr = make_index(arr_h, idx_h);
    let r = eval_entity(&cs, &li, &expr);
    match r {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

#[test]
fn test_length_basic() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![
        entity_ecf::integer(1),
        entity_ecf::integer(2),
        entity_ecf::integer(3),
    ]);
    let arr_h = cs.put(arr).unwrap();
    let expr = make_length(arr_h);
    let r = eval_entity(&cs, &li, &expr);
    assert_eq!(r.as_i128(), Some(3));
}

#[test]
fn test_length_empty_is_zero() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr = make_literal_array(vec![]);
    let arr_h = cs.put(arr).unwrap();
    let expr = make_length(arr_h);
    let r = eval_entity(&cs, &li, &expr);
    assert_eq!(r.as_i128(), Some(0));
}

#[test]
fn test_length_on_null_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arr_h = cs.put(make_literal_null()).unwrap();
    let expr = make_length(arr_h);
    let r = eval_entity(&cs, &li, &expr);
    match r {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

// =====================================================================
// N.4 — Integer arithmetic + compute/numeric-cast (§2.2 rules 8-9, §374)
// =====================================================================

fn make_literal_uint(n: u64) -> Entity {
    // Encode as Value::Integer wrapping a u64. ciborium Integer can hold u64
    // up to its full range — values > i64::MAX are classified as Uint by
    // `int_kind`, giving them uint semantics in arithmetic.
    let data = entity_ecf::cbor_map! {
        "value" => Value::Integer(ciborium::value::Integer::from(n))
    };
    Entity::new(TYPE_LITERAL, entity_ecf::to_ecf(&data)).unwrap()
}

fn make_numeric_cast(value_hash: Hash, to_type: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "to_type" => entity_ecf::text(to_type),
        "value" => Value::Bytes(value_hash.to_bytes().to_vec())
    };
    Entity::new(TYPE_NUMERIC_CAST, entity_ecf::to_ecf(&data)).unwrap()
}

/// Wrap a hash in a `compute/numeric-cast → primitive/uint` so that the
/// immediately-consuming `div`/`mod`/`compare` operation uses unsigned
/// interpretation per §2.2 rule 9. Rule 11 (cast at point-of-use) requires
/// the cast be the direct operand — it does not flow through `compute/let`.
fn cast_to_uint(cs: &MemoryContentStore, value_hash: Hash) -> Hash {
    cs.put(make_numeric_cast(value_hash, TYPE_PRIMITIVE_UINT))
        .unwrap()
}

// v3.16: add/sub/mul are sign-agnostic 64-bit two's-complement (rule 8);
// results encoded canonically signed (rule 10); div/mod/compare are
// signed-default with explicit uint-cast for unsigned interpretation (rule 9).

#[test]
fn test_add_sign_agnostic_positive_and_negative_operand() {
    // Rule 8: `add(3, -1) = 2` is the spec's worked example. No mixed-operand
    // case in v3.16; both operands read as bit patterns.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let l = cs.put(make_literal_int(3)).unwrap();
    let r = cs.put(make_literal_int(-1)).unwrap();
    let expr = make_arithmetic("add", l, r);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(2));
}

#[test]
fn test_add_wraps_at_2_pow_64() {
    // i64::MIN + i64(-1) as bit-pattern add: 0x8000...0000 + 0xFFFF...FFFF
    // = 0x7FFF...FFFF = i64::MAX. Rule 8: wrap mod 2^64; rule 10: signed
    // canonical encoding (bit 63 clear here → major type 0, positive).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let l = cs.put(make_literal_int(i64::MIN)).unwrap();
    let r = cs.put(make_literal_int(-1)).unwrap();
    let expr = make_arithmetic("add", l, r);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(i64::MAX as i128));
}

#[test]
fn test_add_uint_max_plus_one_wraps_to_zero() {
    // u64::MAX bit pattern = -1 as i64. -1 + 1 = 0 (wraps mod 2^64).
    // Rule 10: encoded signed canonical → 0 → major type 0. Result is
    // Primitive(Integer(0)) — no uint tag (the operands were literals, not
    // cast products).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let l = cs.put(make_literal_uint(u64::MAX)).unwrap();
    let r = cs.put(make_literal_int(1)).unwrap();
    let expr = make_arithmetic("add", l, r);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(0));
    // Confirm it's the signed-canonical Primitive form, not a Uint tag.
    assert!(
        matches!(result, ComputeValue::Primitive(Value::Integer(_))),
        "rule 10 expects signed canonical encoding from arithmetic results"
    );
}

#[test]
fn test_unsigned_div_via_uint_cast() {
    // v3.16 rule 9 + rule 11: unsigned div_u reached by casting both operands
    // immediately before the op. Pick a bit pattern with bit 63 set that
    // divides exactly under either interpretation so the result-kind (Uint vs
    // signed Primitive) carries the test signal cleanly.
    //
    // Bit pattern 1<<63 = 0x8000_0000_0000_0000:
    //   - signed: i64::MIN; i64::MIN / 2 = -2^62 (Primitive(Integer))
    //   - unsigned: 2^63;  2^63 / 2 = 2^62 (Uint)
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let two = cs.put(make_literal_int(2)).unwrap();
    let high_cast = cast_to_uint(&cs, high_bit);
    let two_cast = cast_to_uint(&cs, two);
    let expr = make_arithmetic("div", high_cast, two_cast);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Uint(u) => assert_eq!(u, 1u64 << 62),
        other => panic!("expected Uint(2^62), got {:?}", other),
    }
}

#[test]
fn test_signed_div_default_on_high_bit_set_value() {
    // No cast → signed-default per rule 9. Same operand as above but no cast.
    // Signed i64::MIN / 2 = -2^62 (exact, integer result).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let two = cs.put(make_literal_int(2)).unwrap();
    let expr = make_arithmetic("div", high_bit, two);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(-(1i128 << 62)));
}

#[test]
fn test_compare_lt_signed_vs_unsigned_on_high_bit() {
    // Signed: u64::MAX as i64 = -1; -1 < 1 → true.
    // Unsigned (with uint cast): u64::MAX > 1 → lt returns false.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let umax = cs.put(make_literal_uint(u64::MAX)).unwrap();
    let one = cs.put(make_literal_int(1)).unwrap();

    let signed_lt = make_compare("lt", umax, one);
    let r_signed = eval_entity(&cs, &li, &signed_lt);
    match r_signed {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b, "signed -1 < 1"),
        other => panic!("expected Bool, got {:?}", other),
    }

    let umax_u = cast_to_uint(&cs, umax);
    let one_u = cast_to_uint(&cs, one);
    let unsigned_lt = make_compare("lt", umax_u, one_u);
    let r_unsigned = eval_entity(&cs, &li, &unsigned_lt);
    match r_unsigned {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(!b, "unsigned u64::MAX > 1"),
        other => panic!("expected Bool, got {:?}", other),
    }
}

#[test]
fn test_sa1_eval_value_type_entity_returns_as_is() {
    // §2.3 SA-1 (pinned in v3.16): Evaluate(value-type entity) returns it
    // as-is. Verified by handing a pre-built compute/closure entity to
    // evaluate() and confirming the entity passes through (so downstream
    // compute/apply closure-mode can parse it).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let (included, pid) = test_ctx();

    // Build a closure entity directly (not via compute/lambda — we're testing
    // the value-type pass-through, not lambda evaluation).
    let body_h = cs.put(make_literal_int(42)).unwrap();
    let closure_entity = ClosureValue {
        params: vec!["x".into()],
        body: body_h,
        env: None,
    }
    .to_entity();
    assert_eq!(closure_entity.entity_type, TYPE_CLOSURE);

    let mut budget = Budget::default_budget();
    let mut ctx = EvalContext::new(&cs, &li, &included, &pid);
    let result = evaluate(&closure_entity, &Scope::new(), &mut budget, &mut ctx);
    // SA-1: returned as-is. Either ComputeValue::Closure or ComputeValue::Entity
    // carrying the closure entity is acceptable; both round-trip downstream.
    match result {
        ComputeValue::Closure(_) => {}
        ComputeValue::Entity(e) => assert_eq!(e.entity_type, TYPE_CLOSURE),
        other => panic!("SA-1: expected closure/entity, got {:?}", other),
    }
}

#[test]
fn test_mod_with_float_operand_is_type_mismatch() {
    // v3.16 rule 4 update: mod is integer-only; float operand → type_mismatch.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let l = cs.put(make_literal_int(7)).unwrap();
    let r = cs.put(make_literal_float(3.0)).unwrap();
    let expr = make_arithmetic("mod", l, r);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

#[test]
fn test_cast_does_not_flow_through_let() {
    // v3.16 rule 11: `let y = numeric-cast(x, uint) in div(y, 2)` does NOT
    // give unsigned division — the cast is consumed by the binding. Use a
    // bit pattern with bit 63 set that divides exactly under either
    // interpretation so the test signal is signed vs unsigned, not exact-vs-float:
    //   - signed:   i64::MIN / 2 = -2^62 (Primitive(Integer))
    //   - unsigned:  2^63   / 2 =  2^62 (Uint)
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let high_uint_cast = cast_to_uint(&cs, high_bit);
    let two = cs.put(make_literal_int(2)).unwrap();

    let y_ref = cs.put(make_scope_lookup("y")).unwrap();
    let div = cs.put(make_arithmetic("div", y_ref, two)).unwrap();
    let let_expr = make_let(&[("y", high_uint_cast)], div);

    let result = eval_entity(&cs, &li, &let_expr);
    // Cast stripped at binding → signed div → -2^62.
    assert_eq!(result.as_i128(), Some(-(1i128 << 62)));
    assert!(
        matches!(result, ComputeValue::Primitive(Value::Integer(_))),
        "result must be signed Primitive (cast did not flow through let)"
    );
}

#[test]
fn test_cast_at_point_of_use_gives_unsigned() {
    // v3.16 rule 11 contrast: `let y = x in div(numeric-cast(y, uint), 2)`
    // — cast is the direct operand of div, so unsigned interpretation applies.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let two = cs.put(make_literal_int(2)).unwrap();

    let y_ref = cs.put(make_scope_lookup("y")).unwrap();
    let y_cast = cs
        .put(make_numeric_cast(y_ref, TYPE_PRIMITIVE_UINT))
        .unwrap();
    let two_cast = cs
        .put(make_numeric_cast(two, TYPE_PRIMITIVE_UINT))
        .unwrap();
    let div = cs.put(make_arithmetic("div", y_cast, two_cast)).unwrap();
    let let_expr = make_let(&[("y", high_bit)], div);

    let result = eval_entity(&cs, &li, &let_expr);
    // Unsigned 2^63 / 2 = 2^62. Result Uint encodes major type 0.
    match result {
        ComputeValue::Uint(u) => assert_eq!(u, 1u64 << 62),
        other => panic!("expected Uint(2^62), got {:?}", other),
    }
}

#[test]
fn test_cast_through_if_branch_does_not_preserve_intent() {
    // v3.17 SA-AMD3-1 / rule 11: cast intent does NOT flow through a
    // compute/if branch. Mirror of Go's `v317_cast_through_if_branch`:
    //   div(if(true, numeric-cast(x, uint), x), 2) with bit-63-set x
    // The if's then-branch is numeric-cast → uint, but `if` is the
    // direct operand of `div`, not the cast — so per Option A the cast
    // intent is dropped at the if boundary and div uses signed-default.
    //
    // Bit pattern 1<<63 (= i64::MIN signed). Signed div by 2 = -2^62 (exact).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let two = cs.put(make_literal_int(2)).unwrap();
    let cond = cs.put(make_literal_bool(true)).unwrap();
    let high_cast = cs
        .put(make_numeric_cast(high_bit, TYPE_PRIMITIVE_UINT))
        .unwrap();
    let if_expr = cs.put(make_if(cond, high_cast, Some(high_bit))).unwrap();
    let div = make_arithmetic("div", if_expr, two);
    let result = eval_entity(&cs, &li, &div);

    // Signed-default → Primitive(Integer(-2^62)). NOT Uint(2^62).
    assert_eq!(result.as_i128(), Some(-(1i128 << 62)));
    assert!(
        matches!(result, ComputeValue::Primitive(Value::Integer(_))),
        "if-branch must strip cast tag → signed-default div; got {:?}",
        result
    );
}

#[test]
fn test_cast_at_point_of_use_under_if_still_unsigned() {
    // Companion: `if(true, x, x_other)` (no cast in branch) routed through
    // div(numeric-cast(if_result, uint), 2) — here the cast is the direct
    // operand of div, so unsigned interpretation applies. Locks in that the
    // strip only applies to cast-intent *coming out of* the if, not to a
    // cast placed *outside* the if.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let high_bit = cs.put(make_literal_uint(1u64 << 63)).unwrap();
    let two = cs.put(make_literal_int(2)).unwrap();
    let cond = cs.put(make_literal_bool(true)).unwrap();
    let if_expr = cs.put(make_if(cond, high_bit, Some(high_bit))).unwrap();
    let if_cast = cs
        .put(make_numeric_cast(if_expr, TYPE_PRIMITIVE_UINT))
        .unwrap();
    let two_cast = cs
        .put(make_numeric_cast(two, TYPE_PRIMITIVE_UINT))
        .unwrap();
    let div = make_arithmetic("div", if_cast, two_cast);
    let result = eval_entity(&cs, &li, &div);

    match result {
        ComputeValue::Uint(u) => assert_eq!(u, 1u64 << 62),
        other => panic!("expected Uint(2^62), got {:?}", other),
    }
}

#[test]
fn test_canonical_signed_encoding_negative_result() {
    // mul where the signed-interpretation result has bit 63 set: pick small
    // operands whose product's bit-pattern, read signed, is negative.
    // 0x4000_0000_0000_0000 * 2 = 0x8000_0000_0000_0000 (= i64::MIN signed).
    // Rule 10: encoded as major type 1 (negative).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let l = cs.put(make_literal_int(1i64 << 62)).unwrap();
    let r = cs.put(make_literal_int(2)).unwrap();
    let expr = make_arithmetic("mul", l, r);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_i128(), Some(i64::MIN as i128));
}

// --- compute/numeric-cast (§374) ---

#[test]
fn test_cast_int_to_uint_negative_reinterprets() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let neg1 = cs.put(make_literal_int(-1)).unwrap();
    let expr = make_numeric_cast(neg1, TYPE_PRIMITIVE_UINT);
    let result = eval_entity(&cs, &li, &expr);
    // -1 (i64) reinterpreted as u64 → u64::MAX.
    match result {
        ComputeValue::Uint(u) => assert_eq!(u, u64::MAX),
        other => panic!("expected Uint(u64::MAX), got {:?}", other),
    }
}

#[test]
fn test_cast_uint_max_to_int_reinterprets() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let umax = cs.put(make_literal_uint(u64::MAX)).unwrap();
    let expr = make_numeric_cast(umax, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    // u64::MAX reinterpreted as i64 → -1.
    assert_eq!(result.as_i128(), Some(-1));
}

#[test]
fn test_cast_int_to_float() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_int(42)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_FLOAT);
    let result = eval_entity(&cs, &li, &expr);
    assert_eq!(result.as_f64(), Some(42.0));
}

#[test]
fn test_cast_int_to_float_lossy_above_2_53() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    // 2^53 + 1 cannot be represented exactly in f64 — defined-lossy, no error.
    let v = cs.put(make_literal_int((1i64 << 53) + 1)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_FLOAT);
    let result = eval_entity(&cs, &li, &expr);
    // Expect success (no error) and value approximately equal.
    assert!(!result.is_error(), "lossy is not an error");
    assert_eq!(result.as_f64(), Some((1u64 << 53) as f64));
}

#[test]
fn test_cast_float_to_int_truncates() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_float(3.9)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    // Truncate toward zero → 3.
    assert_eq!(result.as_i128(), Some(3));

    let v_neg = cs.put(make_literal_float(-3.9)).unwrap();
    let expr_neg = make_numeric_cast(v_neg, TYPE_PRIMITIVE_INT);
    let result_neg = eval_entity(&cs, &li, &expr_neg);
    assert_eq!(result_neg.as_i128(), Some(-3));
}

#[test]
fn test_cast_nan_to_int_is_cast_out_of_range() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_float(f64::NAN)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::CastOutOfRange(_)) => {}
        other => panic!("expected CastOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_cast_inf_to_int_is_cast_out_of_range() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_float(f64::INFINITY)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::CastOutOfRange(_)) => {}
        other => panic!("expected CastOutOfRange, got {:?}", other),
    }

    let v_n = cs.put(make_literal_float(f64::NEG_INFINITY)).unwrap();
    let expr_n = make_numeric_cast(v_n, TYPE_PRIMITIVE_INT);
    let result_n = eval_entity(&cs, &li, &expr_n);
    match result_n {
        ComputeValue::Error(ComputeError::CastOutOfRange(_)) => {}
        other => panic!("expected CastOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_cast_negative_float_to_uint_is_cast_out_of_range() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_float(-1.5)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_UINT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::CastOutOfRange(_)) => {}
        other => panic!("expected CastOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_cast_huge_float_to_int_is_cast_out_of_range() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    // 2^70 is well outside i64 range.
    let v = cs.put(make_literal_float((1u128 << 70) as f64)).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::CastOutOfRange(_)) => {}
        other => panic!("expected CastOutOfRange, got {:?}", other),
    }
}

#[test]
fn test_cast_null_value_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_null()).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

#[test]
fn test_cast_string_value_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_str("nope")).unwrap();
    let expr = make_numeric_cast(v, TYPE_PRIMITIVE_INT);
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}

// =====================================================================
// N.2 — Builtin handler dispatch via compute/apply (§3.5)
// =====================================================================

#[test]
fn test_apply_to_arithmetic_builtin_alias() {
    // EXTENSION-COMPUTE §3.5 inline alias (cross-impl
    // `v314_builtin_arithmetic_alias`): compute/apply targeting
    // system/compute/builtins/arithmetic produces the same result as the
    // inline form via the in-process intercept.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let three = cs.put(make_literal_int(3)).unwrap();
    let four = cs.put(make_literal_int(4)).unwrap();
    let op_lit = cs.put(make_literal_str("add")).unwrap();
    let apply = make_apply_handler(
        "system/compute/builtins/arithmetic",
        "eval",
        &[("left", three), ("op", op_lit), ("right", four)],
    );
    let result = eval_entity(&cs, &li, &apply);
    assert_eq!(result.as_i128(), Some(7));
}

#[test]
fn test_apply_to_compare_builtin_alias() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let five = cs.put(make_literal_int(5)).unwrap();
    let three = cs.put(make_literal_int(3)).unwrap();
    let op_lit = cs.put(make_literal_str("gt")).unwrap();
    let apply = make_apply_handler(
        "system/compute/builtins/compare",
        "eval",
        &[("left", five), ("op", op_lit), ("right", three)],
    );
    let result = eval_entity(&cs, &li, &apply);
    match result {
        ComputeValue::Primitive(Value::Bool(b)) => assert!(b),
        other => panic!("expected Bool(true), got {:?}", other),
    }
}

#[test]
fn test_apply_to_store_builtin_alias_roundtrip() {
    // Mirror of Go's `v314_builtin_store_roundtrip`:
    // compute/apply(system/compute/builtins/store,
    //               args={path: literal("/peer/.../target"),
    //                     value: literal(uint64(123))})
    // Must dispatch through the alias path, evaluate value (SA-9), wrap the
    // primitive result in primitive/any, and bind to the target path.
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();

    let target_path = format!("/{}/app/test/v316-store-target", TEST_PID);
    let path_lit = cs.put(make_literal_str(&target_path)).unwrap();
    let value_lit = cs.put(make_literal_int(123)).unwrap();

    let apply = make_apply_handler(
        "system/compute/builtins/store",
        "eval",
        &[("path", path_lit), ("value", value_lit)],
    );

    let result = eval_entity(&cs, &li, &apply);
    assert!(
        result.is_truthy(),
        "store should return truthy result, got {:?}",
        result
    );

    // Verify the value landed at the target path.
    let stored_hash = li.get(&target_path).expect("path bound after store");
    let stored_entity = cs.get(&stored_hash).expect("entity present");
    // SA-9 wrapping: bare primitive → primitive/any.
    assert_eq!(stored_entity.entity_type, "primitive/any");
    // Decode the stored data: should be Value::Integer(123).
    let decoded: ciborium::Value =
        ciborium::de::from_reader(stored_entity.data.as_slice()).unwrap();
    match decoded {
        ciborium::Value::Integer(i) => {
            let n: i128 = i.into();
            assert_eq!(n, 123);
        }
        other => panic!("expected stored Integer(123), got {:?}", other),
    }
}

#[test]
fn test_apply_to_field_builtin_alias() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    // Construct an entity with field x=42 inline, then extract via the field
    // builtin's apply alias.
    let v = cs.put(make_literal_int(42)).unwrap();
    let cons = make_construct("app/data", &[("x", v)]);
    let cons_h = cs.put(cons).unwrap();
    let name_lit = cs.put(make_literal_str("x")).unwrap();
    let apply = make_apply_handler(
        "system/compute/builtins/field",
        "eval",
        &[("entity", cons_h), ("name", name_lit)],
    );
    let result = eval_entity(&cs, &li, &apply);
    assert_eq!(result.as_i128(), Some(42));
}

#[test]
fn test_apply_to_unknown_builtin_falls_through() {
    // A path under system/compute/builtins/ but with an unrecognized bare name
    // must fall through to dispatch_execute (so an error/404 happens cleanly).
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let arg = cs.put(make_literal_int(0)).unwrap();
    let apply = make_apply_handler(
        "system/compute/builtins/does-not-exist",
        "eval",
        &[("x", arg)],
    );
    // No dispatch_execute wired and dispatch_builtin won't recognize the
    // bare name → error from missing dispatch_execute.
    let result = eval_entity(&cs, &li, &apply);
    assert!(result.is_error());
}

#[test]
fn test_apply_to_map_builtin_uses_canonical_input_type() {
    // The map builtin has no inline form; verify the params entity built by
    // compute/apply uses the spec-pinned system/compute/map-args type even
    // though no tree handler entity declares it.
    use crate::builtins::builtin_input_type;
    assert_eq!(
        builtin_input_type("system/compute/builtins/map", "eval"),
        Some(TYPE_MAP_ARGS)
    );
    assert_eq!(
        builtin_input_type("system/compute/builtins/filter", "eval"),
        Some(TYPE_FILTER_ARGS)
    );
    assert_eq!(
        builtin_input_type("system/compute/builtins/fold", "eval"),
        Some(TYPE_FOLD_ARGS)
    );
    assert_eq!(
        builtin_input_type("system/compute/builtins/store", "eval"),
        Some(TYPE_STORE_ARGS)
    );
    assert_eq!(
        builtin_input_type("system/compute/builtins/arithmetic", "eval"),
        Some(TYPE_ARITHMETIC)
    );
}

#[test]
fn test_cast_to_bool_is_type_mismatch() {
    let cs = MemoryContentStore::new();
    let li = MemoryLocationIndex::new();
    let v = cs.put(make_literal_int(1)).unwrap();
    let expr = make_numeric_cast(v, "primitive/bool");
    let result = eval_entity(&cs, &li, &expr);
    match result {
        ComputeValue::Error(ComputeError::TypeMismatch(_)) => {}
        other => panic!("expected TypeMismatch, got {:?}", other),
    }
}
