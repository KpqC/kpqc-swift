import Foundation

/// An error returned by a KpqC operation.
public enum KpqCError: Error, Equatable {
    case invalidLength(input: String, expected: Int, actual: Int)
    case contextTooLong(actual: Int)
    case coreFailure(operation: String, status: Int32)
    case invalidOutputLength(output: String, expected: Int, actual: Int)
}

extension KpqCError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .invalidLength(input, expected, actual):
            return "\(input) must be \(expected) bytes, received \(actual)"
        case let .contextTooLong(actual):
            return "context cannot exceed 255 bytes, received \(actual)"
        case let .coreFailure(operation, status):
            return "\(operation) failed with status \(status)"
        case let .invalidOutputLength(output, expected, actual):
            return "cryptographic core returned an invalid \(output) size: expected \(expected), received \(actual)"
        }
    }
}
