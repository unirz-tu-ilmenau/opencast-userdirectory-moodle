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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ExecutionError;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.opencastproject.security.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.PatternSyntaxException;

/**
 * A UserProvider that reads user roles from Moodle.
 */
public class MoodleUserProviderInstance implements UserProvider, RoleProvider, CachingUserProviderMXBean {

  public static final String PROVIDER_NAME = "moodle";

  public static final String MOODLE_FUNCTION_CORE_USER_GET_USERS_BY_FIELD = "core_user_get_users_by_field";

  public static final String MOODLE_FUNCTION_CORE_ENROL_GET_USERS_COURSES = "core_enrol_get_users_courses";

  private static final String LTI_LEARNER_ROLE = "Learner";

  private static final String LTI_INSTRUCTOR_ROLE = "Instructor";

  private static final String OC_USERAGENT = "Opencast";

  /**
   * The logger
   */
  private static final Logger logger = LoggerFactory.getLogger(MoodleUserProviderInstance.class);

  /**
   * A token to store in the miss cache
   */
  private Object nullToken = new Object();

  /**
   * The organization
   */
  private Organization organization;

  /**
   * Total number of requests made to load users
   */
  private AtomicLong requests;

  /**
   * The number of requests made to Moodle
   */
  private AtomicLong moodleLoads;

  /**
   * A cache of users, which lightens the load on Moodle
   */
  private LoadingCache<String, Object> cache;

  /**
   * The URL of the Moodle instance
   */
  private String moodleUrl;

  /**
   * The token used to call Moodle REST webservices
   */
  private String moodleToken;

  /**
   * Regular expression for matching valid courses
   */
  private String coursePattern;

  /**
   * Regular expression for matching valid users
   */
  private String userPattern;

  /**
   * A map of roles which are regarded as Instructor roles
   */
  private Set<String> instructorRoles;

  /**
   * Constructs an Moodle user provider with the needed settings.
   *
   * @param pid             the pid of this service
   * @param organization    the organization
   * @param url             the url of the Moodle server
   * @param token           the authentication token
   * @param coursePattern   the pattern of a Moodle course ID
   * @param userPattern     the pattern of a Moodle user ID
   * @param cacheSize       the number of users to cache
   * @param cacheExpiration the number of minutes to cache users
   */
  public MoodleUserProviderInstance(String pid, Organization organization, String url, String token,
                                    String coursePattern, String userPattern, Set<String> instructorRoles,
                                    int cacheSize, int cacheExpiration) {
    this.organization = organization;
    this.moodleUrl = url;
    this.moodleToken = token;
    this.coursePattern = coursePattern;
    this.userPattern = userPattern;
    this.instructorRoles = instructorRoles;

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    logger.info("Creating new MoodleUserProviderInstance(pid={}, url={}, cacheSize={}, cacheExpiration={})",
        pid, url, cacheSize, cacheExpiration);

    // Setup the caches
    cache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheExpiration, TimeUnit.MINUTES)
        .build(new CacheLoader<String, Object>() {
          @Override
          public Object load(String username) throws Exception {
            User user = loadUserFromMoodle(username);
            return user == null ? nullToken : user;
          }
        });

    registerMBean(pid);
  }


  ////////////////////////////
  // CachingUserProviderMXBean


  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.CachingUserProviderMXBean#getCacheHitRatio()
   */
  @Override
  public float getCacheHitRatio() {
    if (requests.get() == 0)
      return 0;
    return (float) (requests.get() - moodleLoads.get()) / requests.get();
  }

  /**
   * Registers an MXBean.
   */
  private void registerMBean(String pid) {
    // register with jmx
    requests = new AtomicLong();
    moodleLoads = new AtomicLong();
    try {
      ObjectName name;
      name = MoodleUserProviderFactory.getObjectName(pid);
      Object mbean = this;
      MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
      try {
        mbs.unregisterMBean(name);
      } catch (InstanceNotFoundException e) {
        logger.debug("{} was not registered", name);
      }
      mbs.registerMBean(mbean, name);
    } catch (Exception e) {
      logger.error("Unable to register {} as an mbean: {}", this, e);
    }
  }


  ///////////////////////
  // UserProvider methods


  @Override
  public String getName() {
    return PROVIDER_NAME;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#getUsers()
   */
  @Override
  public Iterator<User> getUsers() {
    // We never enumerate all users
    return Collections.emptyIterator();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#loadUser(java.lang.String)
   */
  @Override
  public User loadUser(String userName) {
    requests.incrementAndGet();
    try {
      Object user = cache.getUnchecked(userName);
      if (user == nullToken) {
        logger.debug("Returning null user from cache");
        return null;
      } else {
        logger.debug("Returning user {} from cache", userName);
        return (User) user;
      }
    } catch (ExecutionError e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    } catch (UncheckedExecutionException e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#countUsers()
   */
  @Override
  public long countUsers() {
    // Not meaningful, as we never enumerate users
    return 0;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#getOrganization()
   */
  @Override
  public String getOrganization() {
    return organization.getId();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#findUsers(java.lang.String, int, int)
   */
  @Override
  public Iterator<User> findUsers(String query, int offset, int limit) {
    if (query == null)
      throw new IllegalArgumentException("Query must be set");

    if (query.endsWith("%"))
      query = query.substring(0, query.length() - 1);

    if (query.isEmpty())
      return Collections.emptyIterator();

    // Check if user matches pattern
    try {
      if ((userPattern != null) && !query.matches(userPattern)) {
        logger.debug("verify user {} failed regexp {}", query, userPattern);
        return Collections.emptyIterator();
      }
    } catch (PatternSyntaxException e) {
      logger.warn("Invalid regular expression for user pattern {} - disabling checks", userPattern);
      userPattern = null;
    }

    // Load User
    List<User> users = new LinkedList<>();

    User user = loadUser(query);
    if (user != null)
      users.add(user);

    return users.iterator();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#invalidate(java.lang.String)
   */
  @Override
  public void invalidate(String userName) {
    cache.invalidate(userName);
  }


  ///////////////////////
  // RoleProvider methods


  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.RoleProvider#getRoles()
   */
  @Override
  public Iterator<Role> getRoles() {
    // We won't ever enumerate all Moodle courses, so return an empty list here
    return Collections.emptyIterator();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.RoleProvider#getRolesForUser(java.lang.String)
   */
  @Override
  public List<Role> getRolesForUser(String username) {
    List<Role> roles = new LinkedList<>();

    // Don't answer for admin, anonymous or empty user
    if ("admin".equals(username) || "".equals(username) || "anonymous".equals(username)) {
      logger.debug("we don't answer for: {}", username);
      return roles;
    }

    User user = loadUser(username);
    if (user != null) {
      logger.debug("Returning cached roleset for {}", username);
      return new ArrayList<>(user.getRoles());
    }

    // Not found
    logger.debug("Return empty roleset for {} - not found in Moodle", username);
    return new LinkedList<>();
  }

  /**
   * {@inheritDoc}
   * <p>
   * We search for COURSEID, COURSEID_Learner, COURSEID_Instructor
   *
   * @see org.opencastproject.security.api.RoleProvider#findRoles(java.lang.String, org.opencastproject.security.api.Role.Target, int, int)
   */
  @Override
  public Iterator<Role> findRoles(String query, Role.Target target, int offset, int limit) {
    // Don't return roles for users or groups
    if (target == Role.Target.USER)
      return Collections.emptyIterator();

    boolean exact = true;
    boolean ltirole = false;

    if (query.endsWith("%")) {
      exact = false;
      query = query.substring(0, query.length() - 1);
    }

    if (query.isEmpty())
      return Collections.emptyIterator();

    // Verify that role name ends with LTI_LEARNER_ROLE or LTI_INSTRUCTOR_ROLE
    if (exact
        && !query.endsWith("_" + LTI_LEARNER_ROLE)
        && !query.endsWith("_" + LTI_INSTRUCTOR_ROLE))
      return Collections.emptyIterator();

    // Extract moodle course id
    String moodleCourseId = query;
    if (query.endsWith("_" + LTI_LEARNER_ROLE)) {
      moodleCourseId = query.substring(0, query.lastIndexOf("_" + LTI_LEARNER_ROLE));
      ltirole = true;
    } else if (query.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
      moodleCourseId = query.substring(0, query.lastIndexOf("_" + LTI_INSTRUCTOR_ROLE));
      ltirole = true;
    }

    // Check if course matches pattern
    try {
      if ((coursePattern != null) && !moodleCourseId.matches(coursePattern)) {
        logger.debug("verify course {} failed regexp {}", moodleCourseId, coursePattern);
        return Collections.emptyIterator();
      }
    } catch (PatternSyntaxException e) {
      logger.warn("Invalid regular expression for course pattern {} - disabling checks", coursePattern);
      coursePattern = null;
    }

    // Roles list
    List<Role> roles = new LinkedList<>();
    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);
    if (ltirole) {
      // Query is for a Course ID and an LTI role (Instructor/Learner)
      roles.add(new JaxbRole(query, jaxbOrganization, "Moodle Site Role", Role.Type.EXTERNAL));
    } else {
      // Course ID - return both roles
      roles.add(new JaxbRole(moodleCourseId + "_" + LTI_INSTRUCTOR_ROLE, jaxbOrganization, "Moodle Course Instructor Role", Role.Type.EXTERNAL));
      roles.add(new JaxbRole(moodleCourseId + "_" + LTI_LEARNER_ROLE, jaxbOrganization, "Moodle Course Learner Role", Role.Type.EXTERNAL));
    }

    return roles.iterator();
  }


  /////////////////
  // Helper methods


  /**
   * Load the roles of a User.
   *
   * @param moodleUserId The ID of the Moodle user.
   * @return List of roles.
   */
  private Set<JaxbRole> loadUserRolesFromMoodle(String moodleUserId) {
    logger.debug("loadUserRolesFromMoodle({})", moodleUserId);

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);
    Set<JaxbRole> roles = new HashSet<>();

    // Role for all Moodle users
    roles.add(new JaxbRole(
        Group.ROLE_PREFIX + "MOODLE",
        jaxbOrganization,
        "Moodle Users",
        Role.Type.EXTERNAL_GROUP
    ));

    try {
      List<NameValuePair> params = new ArrayList<>();
      params.add(new BasicNameValuePair("userid", moodleUserId));

      Object obj = executeMoodleRequest(MOODLE_FUNCTION_CORE_ENROL_GET_USERS_COURSES, params);

      if (obj == null)
        return roles;

      if (!(obj instanceof JSONArray))
        throw new Exception("Moodle responded in unexpected format");

      JSONArray courses = (JSONArray) obj;
      for (Object courseObj : courses) {
        JSONObject course = (JSONObject) courseObj;
        String courseId = Long.toString((Long) course.get("id"));

        // Role for Learners
        roles.add(new JaxbRole(
            courseId + "_" + LTI_LEARNER_ROLE,
            jaxbOrganization,
            "Moodle external role",
            Role.Type.EXTERNAL
        ));

        // TODO: check if user is instructor (instructorRoles)      -> courseId + "_" + LTI_INSTRUCTOR_ROLE
        // TODO: check if user is instructor in at least one course -> Group.ROLE_PREFIX + "MOODLE_INSTRUCTOR"
      }
    } catch (Exception e) {
      logger.warn("Exception getting role for Moodle user {} at {}: {}", moodleUserId, moodleUrl, e.getMessage());
    }

    return roles;
  }

  /**
   * Loads a user from Moodle.
   *
   * @param username The username.
   * @return The user.
   */
  private User loadUserFromMoodle(String username) {
    logger.debug("loadUserFromMoodle({})", username);

    if (cache == null)
      throw new IllegalStateException("The Moodle user detail service has not yet been configured");

    // Don't answer for admin, anonymous or empty user
    if ("admin".equals(username) || "".equals(username) || "anonymous".equals(username)) {
      logger.debug("We don't answer for: " + username);
      return null;
    }

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    // update cache statistics
    moodleLoads.incrementAndGet();

    Thread currentThread = Thread.currentThread();
    ClassLoader originalClassloader = currentThread.getContextClassLoader();

    try {
      List<NameValuePair> params = new ArrayList<>();
      params.add(new BasicNameValuePair("field", "username"));
      params.add(new BasicNameValuePair("values[]", username));

      Object obj = executeMoodleRequest(MOODLE_FUNCTION_CORE_USER_GET_USERS_BY_FIELD, params);

      if (obj == null) {
        // user not known to this provider
        logger.debug("User {} not found in Moodle system", username);
        return null;
      }

      if (!(obj instanceof JSONArray))
        throw new Exception("Moodle responded in unexpected format");

      if (((JSONArray) obj).size() == 0)
        return null;

      JSONObject userObj = (JSONObject) ((JSONArray) obj).get(0);
      String userId = Long.toString((Long) userObj.get("id"));
      Set<JaxbRole> roles = loadUserRolesFromMoodle(userId);

      User user = new JaxbUser(
          username,
          null,
          (String) userObj.get("fullname"),
          null,
          PROVIDER_NAME,
          true,
          jaxbOrganization,
          roles
      );

      return user;
    } catch (Exception e) {
      logger.warn("Exception loading Moodle user {} at {}: {}", username, moodleUrl, e.getMessage());
    } finally {
      currentThread.setContextClassLoader(originalClassloader);
    }

    return null;
  }

  /**
   * Executes a Moodle webservice request.
   *
   * @param function The function to execute.
   * @param params   Additional parameters to pass.
   * @return A JSON object, array, String, Number, Boolean, or null.
   * @throws Exception In case of an IO error or if Moodle reports an error.
   */
  private Object executeMoodleRequest(String function, List<NameValuePair> params) throws Exception {
    // Build URL
    URIBuilder url = new URIBuilder(moodleUrl);
    url.addParameters(params);
    url.addParameter("wstoken", moodleToken);
    url.addParameter("wsfunction", function);
    url.addParameter("moodlewsrestformat", "json");

    // Execute request
    HttpGet get = new HttpGet(url.build());
    get.setHeader("User-Agent", OC_USERAGENT);

    try (CloseableHttpClient client = HttpClients.createDefault()) {
      try (CloseableHttpResponse resp = client.execute(get)) {
        // Parse response
        BufferedReader reader = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
        JSONParser parser = new JSONParser();
        Object obj = parser.parse(reader);

        // Check for errors
        if (obj instanceof JSONObject) {
          JSONObject jObj = (JSONObject) obj;
          if (jObj.containsKey("exception") || jObj.containsKey("errorcode"))
            throw new Exception("Moodle returned an error: " + jObj.toJSONString());
        }

        return obj;
      }
    }
  }
}
