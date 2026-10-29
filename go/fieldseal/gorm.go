package fieldseal

import (
	"context"
	"fmt"
	"reflect"

	"gorm.io/gorm/schema"
)

func init() {
	schema.RegisterSerializer("fieldseal", gormSerializer{})
}

type gormSerializer struct{}

// Scan decrypts a column into the model field. Legacy plaintext is left as-is.
func (gormSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) error {
	plain, isNull, err := decryptStored(field.DBName, dbValue)
	if err != nil {
		return err
	}
	target := field.ReflectValueOf(ctx, dst)
	return assignPlaintext(target, field.DBName, plain, isNull)
}

// Value encrypts the model field for INSERT and UPDATE.
func (gormSerializer) Value(_ context.Context, field *schema.Field, _ reflect.Value, fieldValue interface{}) (interface{}, error) {
	plain, isNull, err := plaintextOf(fieldValue)
	if err != nil {
		return nil, err
	}
	if isNull {
		return nil, nil
	}
	encrypted, err := Encrypt(field.DBName, plain)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func decryptStored(column string, dbValue interface{}) (string, bool, error) {
	if dbValue == nil {
		return "", true, nil
	}
	var stored string
	switch v := dbValue.(type) {
	case string:
		stored = v
	case []byte:
		stored = string(v)
	default:
		return "", false, fmt.Errorf("fieldseal db value %T", dbValue)
	}
	plain, err := Decrypt(column, stored)
	if err != nil {
		return "", false, err
	}
	return plain, false, nil
}

func plaintextOf(value interface{}) (string, bool, error) {
	if value == nil {
		return "", true, nil
	}
	switch v := value.(type) {
	case string:
		return v, false, nil
	case *string:
		if v == nil {
			return "", true, nil
		}
		return *v, false, nil
	default:
		return "", false, fmt.Errorf("fieldseal field type %T", value)
	}
}

func assignPlaintext(target reflect.Value, column, plain string, isNull bool) error {
	if !target.CanSet() {
		return fmt.Errorf("fieldseal field %s cannot be set", column)
	}
	switch target.Kind() {
	case reflect.String:
		if isNull {
			target.SetString("")
			return nil
		}
		target.SetString(plain)
		return nil
	case reflect.Pointer:
		if target.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("fieldseal field %s is %s", column, target.Type())
		}
		if isNull {
			target.SetZero()
			return nil
		}
		target.Set(reflect.ValueOf(&plain))
		return nil
	default:
		return fmt.Errorf("fieldseal field %s is %s", column, target.Kind())
	}
}
