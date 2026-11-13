// DNSGuard — Copyright (C) 2026 Miguel Gonzalez Oreiro
// Licensed under the GNU General Public License v3.0 or later. See LICENSE.

// Genera Resources/AppIcon.icns:  swift tools/make_icon.swift
import AppKit

let size: CGFloat = 1024
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext

// Fondo: squircle con degradado
let rect = CGRect(x: 52, y: 52, width: 920, height: 920)
let bg = NSBezierPath(roundedRect: rect, xRadius: 210, yRadius: 210)
bg.addClip()
NSGradient(colors: [NSColor(red: 0.07, green: 0.16, blue: 0.36, alpha: 1),
                    NSColor(red: 0.10, green: 0.45, blue: 0.62, alpha: 1)])!
    .draw(in: rect, angle: -60)

// Escudo
let shield = NSBezierPath()
shield.move(to: NSPoint(x: 512, y: 845))
shield.curve(to: NSPoint(x: 740, y: 775), controlPoint1: NSPoint(x: 600, y: 810), controlPoint2: NSPoint(x: 670, y: 790))
shield.line(to: NSPoint(x: 740, y: 520))
shield.curve(to: NSPoint(x: 512, y: 190), controlPoint1: NSPoint(x: 740, y: 360), controlPoint2: NSPoint(x: 640, y: 250))
shield.curve(to: NSPoint(x: 284, y: 520), controlPoint1: NSPoint(x: 384, y: 250), controlPoint2: NSPoint(x: 284, y: 360))
shield.line(to: NSPoint(x: 284, y: 775))
shield.curve(to: NSPoint(x: 512, y: 845), controlPoint1: NSPoint(x: 354, y: 790), controlPoint2: NSPoint(x: 424, y: 810))
shield.close()
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 30, color: NSColor.black.withAlphaComponent(0.35).cgColor)
NSColor.white.setFill(); shield.fill()
ctx.setShadow(offset: .zero, blur: 0, color: nil)

// Nodos de red dentro del escudo
let teal = NSColor(red: 0.07, green: 0.30, blue: 0.50, alpha: 1)
let center = NSPoint(x: 512, y: 520)
let nodes = [NSPoint(x: 400, y: 650), NSPoint(x: 624, y: 650), NSPoint(x: 400, y: 400), NSPoint(x: 624, y: 400)]
teal.setStroke()
for n in nodes {
    let l = NSBezierPath(); l.lineWidth = 26; l.lineCapStyle = .round
    l.move(to: center); l.line(to: n); l.stroke()
}
for n in nodes {
    NSColor(red: 0.16, green: 0.62, blue: 0.45, alpha: 1).setFill()
    NSBezierPath(ovalIn: NSRect(x: n.x - 46, y: n.y - 46, width: 92, height: 92)).fill()
}
teal.setFill()
NSBezierPath(ovalIn: NSRect(x: center.x - 70, y: center.y - 70, width: 140, height: 140)).fill()
img.unlockFocus()

let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
let png = rep.representation(using: .png, properties: [:])!
try png.write(to: URL(fileURLWithPath: "Resources/icon_1024.png"))
