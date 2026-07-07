package utils

func Get[T any](m map[string]any, key string) (T, bool) {
    v, ok := m[key]
    if !ok {
        var zero T
        return zero, false
    }

    t, ok := v.(T)
    if !ok {
        var zero T
        return zero, false
    }

    return t, true
}
