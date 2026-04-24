package jsonschema

// Property represents a single JSON Schema property definition.
type Property struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Enum        []any               `json:"enum,omitempty"`
	Properties  map[string]Property `json:"properties,omitempty"`
	Items       *Property           `json:"items,omitempty"`
	Required    []string            `json:"required,omitempty"`
}

// Schema is a minimal JSON Schema (draft-07 compatible) used throughout ToolTrust Scanner.
type Schema struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Properties  map[string]Property `json:"properties,omitempty"`
	Required    []string            `json:"required,omitempty"`
	Items       *Property           `json:"items,omitempty"`
}

// PropertyRef captures a schema property together with its fully-qualified path.
type PropertyRef struct {
	Name     string
	Path     string
	Property Property
}

// PropertyNames returns the sorted list of property keys defined in the schema.
func (s Schema) PropertyNames() []string {
	if len(s.Properties) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		names = append(names, k)
	}
	return names
}

// HasProperty reports whether the schema contains a property with the given name.
func (s Schema) HasProperty(name string) bool {
	_, ok := s.Properties[name]
	return ok
}

// WalkProperties visits every schema property, including nested objects and array items.
func (s Schema) WalkProperties(fn func(PropertyRef)) {
	if fn == nil {
		return
	}
	walkPropertyMap("", s.Properties, fn)
	if s.Items != nil {
		walkProperty("[]", *s.Items, fn)
	}
}

// PropertyCount returns the total number of schema properties, including nested ones.
func (s Schema) PropertyCount() int {
	count := 0
	s.WalkProperties(func(_ PropertyRef) {
		count++
	})
	return count
}

func walkPropertyMap(prefix string, props map[string]Property, fn func(PropertyRef)) {
	for name, prop := range props {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		fn(PropertyRef{Name: name, Path: path, Property: prop})
		walkProperty(path, prop, fn)
	}
}

func walkProperty(prefix string, prop Property, fn func(PropertyRef)) {
	if len(prop.Properties) > 0 {
		walkPropertyMap(prefix, prop.Properties, fn)
	}
	if prop.Items != nil {
		itemPath := prefix + "[]"
		fn(PropertyRef{Name: "[]", Path: itemPath, Property: *prop.Items})
		walkProperty(itemPath, *prop.Items, fn)
	}
}
