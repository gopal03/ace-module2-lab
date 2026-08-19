/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = typeof body.orderLinesData === 'string' ? body.orderLinesData : ''
      try {
        if (!isSafeInput(orderLinesData)) {
          throw new Error('Unsafe input detected')
        }
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function isSafeInput (code: string): boolean {
    if (code.includes('\\')) {
      return false
    }
    if (code.includes("'") || code.includes('"') || code.includes('`')) {
      return false
    }
    if (code.includes('[') || code.includes(']')) {
      return false
    }
    const cleanComments = code.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '')
    const normalized = cleanComments.replace(/\s+/g, '').toLowerCase()
    const dangerous = [
      'constructor', 'prototype', '__proto__', 'process', 'global',
      'require', 'child_process', 'exec', 'spawn', 'mainmodule', 'eval', 'this'
    ]
    for (const keyword of dangerous) {
      if (normalized.includes(keyword)) {
        return false
      }
    }
    return true
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
