import Foundation

@inline(never)
internal func secureZeroBytes(_ buffer: UnsafeMutablePointer<UInt8>, _ size: Int) {
    guard size > 0 else { return }
    _ = memset_s(buffer, size, 0, size)
}

internal func secureZeroData(_ data: inout Data) {
    data.withUnsafeMutableBytes { bytes in
        guard let base = bytes.baseAddress else { return }
        secureZeroBytes(base.assumingMemoryBound(to: UInt8.self), bytes.count)
    }
}
