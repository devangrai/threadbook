public enum NetworkRequestAuthorizationGate {
    public static func perform<T>(
        networkAllowed: Bool,
        authorizationIsExact: () -> Bool,
        request: () -> T
    ) -> T? {
        guard !networkAllowed || authorizationIsExact() else {
            return nil
        }
        return request()
    }
}
