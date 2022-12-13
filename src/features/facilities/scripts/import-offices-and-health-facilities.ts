/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * OpenCRVS is also distributed under the terms of the Civil Registration
 * & Healthcare Disclaimer located at http://opencrvs.org/license.
 *
 * Copyright (C) The OpenCRVS Authors. OpenCRVS and the OpenCRVS
 * graphic logo are (registered/a) trademark(s) of Plan International.
 */
import * as fs from 'fs'
import {
  FACILITIES_SOURCE,
  ADMIN_STRUCTURE_SOURCE
} from '@countryconfig/constants'
import chalk from 'chalk'
import { internal } from '@hapi/boom'
import {
  composeAndSaveFacilities,
  generateLocationResource
} from '@countryconfig/features/facilities/scripts/utils'
import { ILocation, readCSVToJSON } from '@countryconfig/features/utils'

const locations = JSON.parse(
  fs.readFileSync(`${ADMIN_STRUCTURE_SOURCE}tmp/fhirLocations.json`).toString()
)

export default async function importFacilities() {
  let crvsOfficeLocations: fhir.Location[]
  let healthFacilityLocations: fhir.Location[]

  const crvsOffices: any = await readCSVToJSON(process.argv[2])
  const healthFacilities: any = await readCSVToJSON(process.argv[3])

  try {
    // tslint:disable-next-line:no-console
    console.log(
      `${chalk.blueBright(
        '/////////////////////////// MAPPING CR OFFICES TO LOCATIONS AND SAVING TO FHIR ///////////////////////////'
      )}`
    )
    crvsOfficeLocations = await composeAndSaveFacilities(
      crvsOffices,
      locations.previousLevelLocations
    )
    healthFacilityLocations = await composeAndSaveFacilities(
      healthFacilities,
      locations.previousLevelLocations
    )

    const fhirLocations: fhir.Location[] = []
    fhirLocations.push(...crvsOfficeLocations)
    fhirLocations.push(...healthFacilityLocations)
    const data: ILocation[] = []
    for (const location of fhirLocations) {
      data.push(generateLocationResource(location))
    }
    fs.writeFileSync(
      `${FACILITIES_SOURCE}tmp/locations.json`,
      JSON.stringify({ data }, null, 2)
    )
  } catch (err) {
    return internal(err)
  }

  return true
}

importFacilities()