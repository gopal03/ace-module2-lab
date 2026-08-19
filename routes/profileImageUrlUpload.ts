/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'
import { promisify } from 'node:util'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const dnsLookup = promisify(dns.lookup)

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return true

  const [p0, p1, p2, p3] = parts

  if (p0 === 127) return true // Loopback
  if (p0 === 10) return true // Private
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true // Private
  if (p0 === 192 && p1 === 168) return true // Private
  if (p0 === 169 && p1 === 254) return true // Link-local
  if (p0 === 0) return true // Broadcast/current
  if (p0 === 100 && p1 >= 64 && p1 <= 127) return true // CGNAT
  if (p0 === 198 && (p1 === 18 || p1 === 19)) return true // Benchmark
  if (p0 >= 224) return true // Multicast / Reserved

  return false
}

function preReplaceIPv4 (ip: string): string {
  const parts = ip.split(':')
  const lastPart = parts[parts.length - 1]
  if (net.isIPv4(lastPart)) {
    const octets = lastPart.split('.').map(Number)
    const g1 = octets[0].toString(16).padStart(2, '0') + octets[1].toString(16).padStart(2, '0')
    const g2 = octets[2].toString(16).padStart(2, '0') + octets[3].toString(16).padStart(2, '0')
    parts[parts.length - 1] = `${g1}:${g2}`
    return parts.join(':')
  }
  return ip
}

function expandIPv6 (ip: string): string | null {
  const normalizedIp = preReplaceIPv4(ip)
  const parts = normalizedIp.split(':')
  if (parts.length < 3 || parts.length > 9) return null

  const doubleColonIndex = normalizedIp.indexOf('::')
  let fullParts: string[] = []
  if (doubleColonIndex !== -1) {
    const left = normalizedIp.slice(0, doubleColonIndex).split(':').filter(Boolean)
    const right = normalizedIp.slice(doubleColonIndex + 2).split(':').filter(Boolean)
    const missingCount = 8 - (left.length + right.length)
    if (missingCount < 0) return null

    fullParts = [
      ...left,
      ...Array(missingCount).fill('0'),
      ...right
    ]
  } else {
    fullParts = parts
  }

  if (fullParts.length !== 8) return null

  const expanded = fullParts.map(part => {
    const val = part.trim()
    if (val === '') return '0000'
    const hex = parseInt(val, 16)
    if (isNaN(hex)) return '0000'
    return hex.toString(16).padStart(4, '0')
  })

  return expanded.join(':')
}

function isPrivateIPv6 (ip: string): boolean {
  const expanded = expandIPv6(ip)
  if (expanded === null) return true // Safe fallback if parsing fails

  // Loopback ::1
  if (expanded === '0000:0000:0000:0000:0000:0000:0000:0001') return true
  // Unspecified ::
  if (expanded === '0000:0000:0000:0000:0000:0000:0000:0000') return true

  // Unique local address (ULA): fc00::/7
  // Starts with 'fc' or 'fd'
  const firstGroup = expanded.split(':')[0]
  if (firstGroup.startsWith('fc') || firstGroup.startsWith('fd')) return true

  // Link-local: fe80::/10
  // Starts with 'fe8', 'fe9', 'fea', 'feb'
  if (firstGroup.startsWith('fe8') || firstGroup.startsWith('fe9') || firstGroup.startsWith('fea') || firstGroup.startsWith('feb')) return true

  // Multicast: ff00::/8
  // Starts with 'ff'
  if (firstGroup.startsWith('ff')) return true

  // IPv4-mapped IPv6: ::ffff:0:0/96
  if (expanded.startsWith('0000:0000:0000:0000:0000:ffff:')) {
    const ipv4Part = ip.split(':').pop()
    if (ipv4Part !== undefined && net.isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part)
    }
    const hexParts = expanded.split(':').slice(-2)
    const p1 = parseInt(hexParts[0].substring(0, 2), 16)
    const p2 = parseInt(hexParts[0].substring(2, 4), 16)
    const p3 = parseInt(hexParts[1].substring(0, 2), 16)
    const p4 = parseInt(hexParts[1].substring(2, 4), 16)
    return isPrivateIPv4(`${p1}.${p2}.${p3}.${p4}`)
  }

  // IPv4-compatible IPv6 (deprecated)
  if (expanded.startsWith('0000:0000:0000:0000:0000:0000:')) {
    const ipv4Part = ip.split(':').pop()
    if (ipv4Part !== undefined && net.isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part)
    }
    const hexParts = expanded.split(':').slice(-2)
    const p1 = parseInt(hexParts[0].substring(0, 2), 16)
    const p2 = parseInt(hexParts[0].substring(2, 4), 16)
    const p3 = parseInt(hexParts[1].substring(0, 2), 16)
    const p4 = parseInt(hexParts[1].substring(2, 4), 16)
    return isPrivateIPv4(`${p1}.${p2}.${p3}.${p4}`)
  }

  return false
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)

    // Check protocol: must be http: or https:
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    let hostname = parsedUrl.hostname

    // Strip square brackets from IPv6 hostnames
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1)
    }

    // Strip trailing dot if present
    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1)
    }

    if (hostname === '') {
      return false
    }

    // Direct IP check: if the hostname itself is an IP address
    if (net.isIP(hostname) !== 0) {
      if (net.isIPv4(hostname)) {
        return !isPrivateIPv4(hostname)
      } else if (net.isIPv6(hostname)) {
        return !isPrivateIPv6(hostname)
      }
      return false
    }

    // Explicitly block "localhost" just in case
    const lowerHost = hostname.toLowerCase()
    if (lowerHost === 'localhost' || lowerHost.endsWith('.local')) {
      return false
    }

    // DNS Lookup to get all associated IP addresses
    const addresses = await dnsLookup(hostname, { all: true })
    if (addresses === undefined || addresses.length === 0) {
      return false
    }

    for (const { address } of addresses) {
      if (net.isIPv4(address)) {
        if (isPrivateIPv4(address)) {
          return false
        }
      } else if (net.isIPv6(address)) {
        if (isPrivateIPv6(address)) {
          return false
        }
      } else {
        return false // Unknown IP family
      }
    }

    return true
  } catch (error) {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string') {
        res.status(400)
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const isSafe = await isSafeUrl(url)
        if (!isSafe) {
          res.status(400)
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
