// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "EcliptixOPAQUE",
            targets: ["EcliptixOPAQUESwift"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/releases/download/v2.0.0/EcliptixOPAQUE.xcframework.zip",
            checksum: "1d9570eb94989899d55dfe52657ae44118a2d516c9e5a18c9b8ecf56f30946fe"
        ),
        .target(
            name: "EcliptixOPAQUESwift",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "swift/Sources/EcliptixOPAQUE"
        )
    ]
)
