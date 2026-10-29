// Native macOS prompt for the secret-handoff skill.
// Shows the request, takes the value in a masked field, and writes it to a
// private temp file. The calling process never sees the value on stdout.
//
// Build: swiftc -O secrethud.swift -o .build/secrethud
// Usage: secrethud --name T --for W --hint H --ttl 24 --out /tmp/x

import AppKit
import Foundation

func arg(_ key: String) -> String? {
    let a = CommandLine.arguments
    if let i = a.firstIndex(of: key), i + 1 < a.count { return a[i + 1] }
    return nil
}

let reqName = arg("--name") ?? "Secret"
let reqWhy = arg("--for") ?? ""
let reqHint = arg("--hint") ?? ""
let outPath = arg("--out") ?? ""
let ttlText = arg("--ttl") ?? "24"

let unit = (Double(ttlText) == 1) ? "hour" : "hours"

let ttlClean: String = {
    if let d = Double(ttlText), d == d.rounded() { return String(Int(d)) }
    return ttlText
}()

let bg = NSColor(srgbRed: 0.086, green: 0.094, blue: 0.106, alpha: 1)
let card = NSColor(srgbRed: 0.125, green: 0.136, blue: 0.153, alpha: 1)
let fg = NSColor(white: 0.96, alpha: 1)
let dim = NSColor(srgbRed: 0.62, green: 0.65, blue: 0.70, alpha: 1)
let blue = NSColor(srgbRed: 0.16, green: 0.47, blue: 0.98, alpha: 1)

final class PromptWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

final class Flipped: NSView {
    override var isFlipped: Bool { true }
}

func linkified(_ s: String, font: NSFont, color: NSColor) -> NSAttributedString {
    let out = NSMutableAttributedString(string: s, attributes: [.font: font, .foregroundColor: color])
    if let det = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) {
        det.enumerateMatches(in: s, options: [], range: NSRange(location: 0, length: (s as NSString).length)) { m, _, _ in
            guard let m = m, let url = m.url else { return }
            out.addAttribute(.link, value: url, range: m.range)
        }
    }
    return out
}

final class Delegate: NSObject, NSApplicationDelegate, NSTextFieldDelegate {
    var win: NSWindow!
    let field = NSSecureTextField()
    var saveBtn: NSButton!
    var accepted = false

    func applicationDidFinishLaunching(_ note: Notification) {
        let width: CGFloat = 680
        let pad: CGFloat = 30
        let inner = width - pad * 2
        let titleFont = NSFont.systemFont(ofSize: 17, weight: .semibold)
        let descFont = NSFont.systemFont(ofSize: 14.5)
        let fieldH: CGFloat = 40
        let saveW: CGFloat = 170

        let pieces = [reqWhy, reqHint].filter { !$0.isEmpty }
        let descString = pieces.joined(separator: "\n")
        let descAttr = linkified(descString, font: descFont, color: dim)
        let storage = NSTextStorage(attributedString: descAttr)
        let container = NSTextContainer(size: NSSize(width: inner - 4, height: .greatestFiniteMagnitude))
        container.lineFragmentPadding = 0
        let layout = NSLayoutManager()
        layout.addTextContainer(container)
        storage.addLayoutManager(layout)
        layout.ensureLayout(for: container)
        let descH = max(layout.usedRect(for: container).height.rounded(.up) + 6, 18)

        var contentH: CGFloat = pad
        contentH += 24 + 12
        contentH += descH + 24
        contentH += fieldH + 20
        contentH += 20 + pad

        win = PromptWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: contentH),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        win.backgroundColor = .clear
        win.isOpaque = false
        win.hasShadow = true
        win.isReleasedWhenClosed = false
        win.isMovableByWindowBackground = true
        win.level = .floating
        win.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        win.center()

        let root = Flipped(frame: NSRect(x: 0, y: 0, width: width, height: contentH))
        root.wantsLayer = true
        root.layer?.backgroundColor = bg.cgColor
        root.layer?.cornerRadius = 14
        root.layer?.masksToBounds = true
        win.contentView = root

        var y: CGFloat = pad

        let title = NSTextField(labelWithString: reqName)
        title.font = titleFont
        title.textColor = fg
        title.lineBreakMode = .byTruncatingTail
        title.frame = NSRect(x: pad, y: y, width: inner, height: 24)
        root.addSubview(title)
        y += 24 + 12

        let desc = NSTextField(labelWithAttributedString: descAttr)
        desc.isSelectable = true
        desc.isEditable = false
        desc.allowsEditingTextAttributes = false
        desc.drawsBackground = false
        desc.isBezeled = false
        desc.frame = NSRect(x: pad, y: y, width: inner, height: descH)
        desc.cell?.wraps = true
        root.addSubview(desc)
        y += descH + 24

        let well = NSView(frame: NSRect(x: pad, y: y, width: inner - saveW - 12, height: fieldH))
        well.wantsLayer = true
        well.layer?.cornerRadius = 9
        well.layer?.backgroundColor = card.cgColor
        well.layer?.borderWidth = 1.5
        well.layer?.borderColor = blue.cgColor
        root.addSubview(well)

        field.frame = NSRect(x: 13, y: (fieldH - 20) / 2, width: well.bounds.width - 26, height: 20)
        field.font = NSFont.systemFont(ofSize: 15)
        field.isBezeled = false
        field.drawsBackground = false
        field.textColor = fg
        field.focusRingType = .none
        field.placeholderString = "Paste the secret here"
        field.delegate = self
        well.addSubview(field)

        saveBtn = NSButton(title: "Save securely", target: self, action: #selector(saveTapped))
        saveBtn.frame = NSRect(x: pad + inner - saveW, y: y, width: saveW, height: fieldH)
        saveBtn.isBordered = false
        saveBtn.wantsLayer = true
        saveBtn.layer?.cornerRadius = 9
        saveBtn.layer?.backgroundColor = blue.cgColor
        saveBtn.attributedTitle = NSAttributedString(
            string: "Save securely",
            attributes: [
                .foregroundColor: NSColor.white,
                .font: NSFont.systemFont(ofSize: 15, weight: .semibold),
            ]
        )
        saveBtn.keyEquivalent = "\r"
        saveBtn.isEnabled = false
        saveBtn.layer?.backgroundColor = NSColor(srgbRed: 0.16, green: 0.30, blue: 0.55, alpha: 1).cgColor
        root.addSubview(saveBtn)
        y += fieldH + 20

        let footIcon = NSTextField(labelWithString: "\u{1F512}")
        footIcon.font = NSFont.systemFont(ofSize: 12)
        footIcon.frame = NSRect(x: pad, y: y, width: 16, height: 16)
        root.addSubview(footIcon)

        let foot = NSTextField(
            labelWithString: "Kept out of chat, in a private file this agent's commands can read for \(ttlClean) \(unit)"
        )
        foot.font = NSFont.systemFont(ofSize: 12)
        foot.textColor = dim
        foot.frame = NSRect(x: pad + 20, y: y, width: inner - 100, height: 16)
        root.addSubview(foot)

        let decline = NSButton(title: "Decline", target: self, action: #selector(declineTapped))
        decline.frame = NSRect(x: pad + inner - 78, y: y - 3, width: 78, height: 20)
        decline.isBordered = false
        decline.attributedTitle = NSAttributedString(
            string: "Decline",
            attributes: [
                .foregroundColor: dim,
                .font: NSFont.systemFont(ofSize: 12.5),
            ]
        )
        decline.keyEquivalent = "\u{1b}"
        decline.keyEquivalentModifierMask = []
        root.addSubview(decline)

        win.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        win.makeFirstResponder(field)
    }

    func controlTextDidChange(_ note: Notification) {
        saveBtn.isEnabled = !field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        saveBtn.layer?.backgroundColor = saveBtn.isEnabled ? blue.cgColor : NSColor(white: 0.3, alpha: 1).cgColor
    }

    @objc func saveTapped() {
        let value = field.stringValue
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let tmp = outPath + ".partial"
        let data = Data(value.utf8)
        let ok = FileManager.default.createFile(
            atPath: tmp,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        )
        if ok, (try? FileManager.default.moveItem(atPath: tmp, toPath: outPath)) != nil {
            accepted = true
        } else {
            FileHandle.standardError.write(Data("could not write the secret file\n".utf8))
            accepted = false
        }
        NSApp.terminate(nil)
    }

    @objc func declineTapped() {
        accepted = false
        NSApp.terminate(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ note: Notification) {
        exit(accepted ? 0 : 2)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = Delegate()
app.delegate = delegate
app.run()
