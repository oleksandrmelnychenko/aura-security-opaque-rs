// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraOPAQUE",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "AuraOPAQUE",
            targets: ["AuraOPAQUESwift"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "AuraOPAQUEBinary",
            url: "https://github.com/oleksandrmelnychenko/aura-security-opaque-rs/releases/download/v2.0.0/AuraOPAQUE.xcframework.zip",
            checksum: "1d9570eb94989899d55dfe52657ae44118a2d516c9e5a18c9b8ecf56f30946fe"
        ),
        .target(
            name: "AuraOPAQUESwift",
            dependencies: ["AuraOPAQUEBinary"],
            path: "swift/Sources/AuraOPAQUE"
        )
    ]
)
