// Copyright 2017 The WWU eLectures Team All rights reserved.
//
// Licensed under the Educational Community License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://opensource.org/licenses/ECL-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.opencastproject.userdirectory.moodle;

import org.apache.commons.collections.IteratorUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opencastproject.security.api.DefaultOrganization;
import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.User;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

public class MoodleUserProviderTest {

  private MoodleUserProviderInstance moodleProvider;

  @Before
  public void setUp() throws Exception {
    Set<String> instructorRoles = new HashSet<>();
    instructorRoles.add("Site owner");
    instructorRoles.add("Instructor");
    instructorRoles.add("maintain");

    moodleProvider = new MoodleUserProviderInstance(
        "sample_pid", new DefaultOrganization(), "http://moodle/webservice/rest/server.php", "myToken",
        "^[0-9]+$", "^[0-9a-zA-Z_]+$", instructorRoles, 100, 10
    );
  }

  @Test
  @Ignore
  public void testLoadUser() throws Exception {
    User user = moodleProvider.loadUser("m_neug03");
    assertNotNull(user);

    // Generic group role added for all Moodle users
    assertTrue(hasRole(user.getRoles(), "ROLE_GROUP_MOODLE"));

    // Test role specific to user datest on test Moodle instances
    // TODO: add test for instractor
    assertTrue(hasRole(user.getRoles(), "20686_Learner"));

    user = moodleProvider.loadUser("nobody");
    assertNull(user);
  }

  @Test
  @Ignore
  public void testFindUser() throws Exception {
    // User exists
    assertEquals(1, IteratorUtils.toList(moodleProvider.findUsers("m_neug03", 0, 1)).size());

    // User exists but fails regexp pattern (minimum 6 characters)
    assertEquals(0, IteratorUtils.toList(moodleProvider.findUsers("admin", 0, 1)).size());

    // User doesn't exist
    assertEquals(0, IteratorUtils.toList(moodleProvider.findUsers("nobody", 0, 1)).size());
  }

  @Test
  @Ignore
  public void testFindRoles() throws Exception {
    // Site exists
    assertEquals(2, IteratorUtils.toList(moodleProvider.findRoles("20686%", Role.Target.ACL, 0, 2)).size());
    assertEquals(1, IteratorUtils.toList(moodleProvider.findRoles("20686_Learner", Role.Target.ACL, 0, 1)).size());
    assertEquals(1, IteratorUtils.toList(moodleProvider.findRoles("20686_Instructor", Role.Target.ACL, 0, 1)).size());
    assertEquals(1, IteratorUtils.toList(moodleProvider.findRoles("20686_Instructor%", Role.Target.ACL, 0, 1)).size());

    // Site fails pattern
    assertEquals(0, IteratorUtils.toList(moodleProvider.findRoles("!gateway%", Role.Target.ACL, 0, 2)).size());

    // Site or role does not exist
    assertEquals(0, IteratorUtils.toList(moodleProvider.findRoles("20686__Learner", Role.Target.ACL, 0, 1)).size());
    assertEquals(0, IteratorUtils.toList(moodleProvider.findRoles("20686_", Role.Target.ACL, 0, 1)).size());
  }

  private boolean hasRole(Set<Role> roles, String roleName) {
    for (Role role : roles)
      if (roleName.equals(role.getName()))
        return true;

    return false;
  }
}
